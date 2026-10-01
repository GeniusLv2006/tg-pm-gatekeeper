// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 GeniusLv2006 and contributors
(() => {
  const root = document.body;
  if (!root.hasAttribute('data-dashboard-page')) return;
  const capabilityRoot = `/${location.pathname.split('/')[1]}`;
  const connection = document.querySelector('[data-connection]');
  const connectionLabel = document.querySelector('[data-connection-label]');
  const checkedAt = document.querySelector('[data-checked-at]');
  const refreshButton = document.querySelector('[data-dashboard-refresh]');
  let timer;
  let refreshController;
  let navigationController;
  let navigating = false;

  const setConnection = (state, label, timestamp) => {
    if (!connection || !connectionLabel || !checkedAt) return;
    connection.dataset.state = state;
    connectionLabel.textContent = label;
    if (timestamp) checkedAt.textContent = `Checked ${timestamp}`;
  };

  const fetchPage = async (url, signal) => {
    const response = await fetch(url, {
      cache: 'no-store', credentials: 'same-origin', signal,
      headers: {'X-Dashboard-Refresh': '1'},
    });
    if (!response.ok) throw new Error(`page refresh failed: ${response.status}`);
    const nextDocument = new DOMParser().parseFromString(await response.text(), 'text/html');
    if (!nextDocument.body.hasAttribute('data-dashboard-page')) {
      throw new Error('dashboard session unavailable');
    }
    return nextDocument;
  };

  const updateSection = (nextDocument) => {
    const currentSection = document.querySelector('[data-section-indicator]');
    const nextSection = nextDocument.querySelector('[data-section-indicator]');
    if (currentSection && nextSection) currentSection.replaceWith(nextSection);
  };

  const replaceLiveRegions = (nextDocument) => {
    const nextRegions = new Map(
      Array.from(nextDocument.querySelectorAll('[data-live-region]')).map(
        (region) => [region.dataset.liveRegion, region]
      )
    );
    document.querySelectorAll('[data-live-region]').forEach((region) => {
      const replacement = nextRegions.get(region.dataset.liveRegion);
      if (!replacement) return;
      region.querySelectorAll('input:not([type="hidden"]), textarea, select').forEach((control) => {
        const key = control.id || control.name;
        if (!key) return;
        const nextControl = Array.from(
          replacement.querySelectorAll('input:not([type="hidden"]), textarea, select')
        ).find((candidate) => (candidate.id || candidate.name) === key);
        if (nextControl) {
          nextControl.value = control.value;
          if ('checked' in control) nextControl.checked = control.checked;
        }
      });
      // Polling must not collapse context or move a horizontally scrolled table.
      const previousDetails = region.querySelectorAll('details');
      replacement.querySelectorAll('details').forEach((element, index) => {
        if (previousDetails[index]) element.open = previousDetails[index].open;
      });
      const tableScroll = Array.from(region.querySelectorAll('.table-shell'))
        .map((element) => element.scrollLeft);
      const active = region.contains(document.activeElement) ? document.activeElement : null;
      const activeKey = active && (active.id || active.name);
      region.replaceWith(replacement);
      replacement.querySelectorAll('.table-shell').forEach((element, index) => {
        element.scrollLeft = tableScroll[index] || 0;
      });
      if (activeKey) {
        const nextActive = Array.from(replacement.querySelectorAll('input, textarea, select, button, a'))
          .find((candidate) => (candidate.id || candidate.name) === activeKey);
        nextActive?.focus({preventScroll: true});
      }
    });
    updateSection(nextDocument);
    root.dataset.pageVersion = nextDocument.body.dataset.pageVersion;
  };

  const markChanged = () => {
    const changeNotice = document.querySelector('[data-change-notice]');
    if (!changeNotice) return;
    changeNotice.hidden = false;
    document.querySelectorAll('form:not(.logout-form) button').forEach((button) => {
      button.disabled = true;
    });
  };

  const check = async ({force = false} = {}) => {
    const mode = root.dataset.liveRefresh;
    if (!mode || refreshController || navigating ||
        (!force && document.visibilityState !== 'visible')) return;
    const controller = new AbortController();
    refreshController = controller;
    if (refreshButton) refreshButton.disabled = true;
    // Bound both the status request and the subsequent HTML refresh.
    const timeout = window.setTimeout(() => controller.abort(), 4000);
    try {
      const logicalTarget = location.pathname.slice(capabilityRoot.length) + location.search;
      const response = await fetch(
        `${capabilityRoot}/dashboard/status?path=${encodeURIComponent(logicalTarget)}`,
        {cache: 'no-store', credentials: 'same-origin', signal: controller.signal}
      );
      if (!response.ok) throw new Error(`status check failed: ${response.status}`);
      const status = await response.json();
      if (controller.signal.aborted) return;
      setConnection('connected', 'Connected', status.checked_at);
      if (force || status.version !== root.dataset.pageVersion) {
        if (mode === 'replace') {
          const nextDocument = await fetchPage(location.pathname + location.search, controller.signal);
          if (controller.signal.aborted) return;
          replaceLiveRegions(nextDocument);
        } else if (status.version !== root.dataset.pageVersion) {
          markChanged();
          root.dataset.pageVersion = status.version;
        }
      }
    } catch (_error) {
      if (refreshController === controller && !navigating) {
        setConnection('disconnected', 'Disconnected', 'retrying');
      }
    } finally {
      window.clearTimeout(timeout);
      if (refreshController === controller) {
        refreshController = undefined;
        if (refreshButton) refreshButton.disabled = false;
      }
    }
  };

  const schedule = () => {
    window.clearInterval(timer);
    if (!navigating && root.dataset.liveRefresh && document.visibilityState === 'visible') {
      check();
      timer = window.setInterval(check, Number(root.dataset.pollSeconds) * 1000);
    }
  };

  const navigate = async (url, {pop = false, scroll = [0, 0]} = {}) => {
    navigationController?.abort();
    refreshController?.abort();
    refreshController = undefined;
    window.clearInterval(timer);
    const controller = new AbortController();
    navigationController = controller;
    navigating = true;
    if (refreshButton) refreshButton.disabled = true;
    const timeout = window.setTimeout(() => controller.abort(), 10000);
    const content = document.querySelector('[data-dashboard-content]');
    content?.setAttribute('aria-busy', 'true');
    try {
      const nextDocument = await fetchPage(url, controller.signal);
      if (navigationController !== controller) return;
      const nextContent = nextDocument.querySelector('[data-dashboard-content]');
      if (!content || !nextContent) throw new Error('dashboard content unavailable');
      if (!pop) {
        history.replaceState({...history.state, dashboardScroll: [window.scrollX, window.scrollY]}, '');
        history.pushState({dashboardScroll: scroll}, '', url);
      }
      content.replaceWith(nextContent);
      updateSection(nextDocument);
      document.title = nextDocument.title;
      for (const key of ['liveRefresh', 'pageVersion', 'pollSeconds']) {
        if (nextDocument.body.dataset[key]) root.dataset[key] = nextDocument.body.dataset[key];
        else delete root.dataset[key];
      }
      const main = nextContent.querySelector('main');
      main?.setAttribute('tabindex', '-1');
      main?.focus({preventScroll: true});
      window.scrollTo(...scroll);
    } catch (_error) {
      // Preserve normal navigation for expired sessions and unavailable routes.
      if (navigationController === controller) location.assign(url);
    } finally {
      window.clearTimeout(timeout);
      if (navigationController === controller) {
        navigating = false;
        navigationController = undefined;
        content?.removeAttribute('aria-busy');
        if (refreshButton) refreshButton.disabled = false;
        schedule();
      }
    }
  };

  document.addEventListener('click', (event) => {
    const link = event.target.closest('a[href]');
    if (!link || event.defaultPrevented || event.button !== 0 ||
        event.metaKey || event.ctrlKey || event.shiftKey || event.altKey ||
        link.hasAttribute('download') || (link.target && link.target !== '_self')) return;
    const url = new URL(link.href, location.href);
    if (url.origin !== location.origin || url.hash ||
        !url.pathname.startsWith(`${capabilityRoot}/`)) return;
    const path = url.pathname.slice(capabilityRoot.length);
    if (!/^\/(?:$|cases(?:\/|$)|review(?:\/|$)|enforcement(?:\/|$))/.test(path)) return;
    event.preventDefault();
    navigate(url.href);
  });
  history.scrollRestoration = 'manual';
  window.addEventListener('popstate', (event) => {
    navigate(location.href, {pop: true, scroll: event.state?.dashboardScroll || [0, 0]});
  });
  refreshButton?.addEventListener('click', () => {
    const changeNotice = document.querySelector('[data-change-notice]');
    if (root.dataset.liveRefresh === 'notice' && changeNotice && !changeNotice.hidden) {
      navigate(location.href, {pop: true, scroll: [window.scrollX, window.scrollY]});
      return;
    }
    check({force: true});
  });
  window.addEventListener('pagehide', () => {
    window.clearInterval(timer);
    refreshController?.abort();
    navigationController?.abort();
    refreshController = undefined;
    navigationController = undefined;
    navigating = false;
  });
  window.addEventListener('pageshow', schedule);
  document.addEventListener('visibilitychange', schedule);
  schedule();
})();
