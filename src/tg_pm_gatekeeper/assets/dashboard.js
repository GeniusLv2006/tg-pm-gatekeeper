(() => {
  const root = document.body;
  const mode = root.dataset.liveRefresh;
  let version = root.dataset.pageVersion;
  let timer;
  let checking = false;

  const connection = document.querySelector('[data-connection]');
  const connectionLabel = document.querySelector('[data-connection-label]');
  const checkedAt = document.querySelector('[data-checked-at]');
  const refreshButton = document.querySelector('[data-dashboard-refresh]');
  const changeNotice = document.querySelector('[data-change-notice]');

  if (!mode || !version || !connection || !connectionLabel || !checkedAt) return;

  const setConnection = (state, label, timestamp) => {
    connection.dataset.state = state;
    connectionLabel.textContent = label;
    if (timestamp) checkedAt.textContent = `Checked ${timestamp}`;
  };

  const replaceLiveRegions = async () => {
    const response = await fetch(location.pathname + location.search, {
      cache: 'no-store',
      credentials: 'same-origin',
      headers: {'X-Dashboard-Refresh': '1'},
    });
    if (!response.ok) throw new Error(`page refresh failed: ${response.status}`);
    const nextDocument = new DOMParser().parseFromString(await response.text(), 'text/html');
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
        if (nextControl) nextControl.value = control.value;
      });
      const active = region.contains(document.activeElement) ? document.activeElement : null;
      const activeKey = active && (active.id || active.name);
      region.replaceWith(replacement);
      if (activeKey) {
        const nextActive = Array.from(replacement.querySelectorAll('input, textarea, select, button, a'))
          .find((candidate) => (candidate.id || candidate.name) === activeKey);
        nextActive?.focus({preventScroll: true});
      }
    });
    const currentSection = document.querySelector('[data-section-indicator]');
    const nextSection = nextDocument.querySelector('[data-section-indicator]');
    if (currentSection && nextSection) currentSection.replaceWith(nextSection);
  };

  const markChanged = () => {
    if (!changeNotice) return;
    changeNotice.hidden = false;
    document.querySelectorAll('form:not(.logout-form) button').forEach((button) => {
      button.disabled = true;
    });
  };

  const check = async ({force = false} = {}) => {
    if (checking || (!force && document.visibilityState !== 'visible')) return;
    checking = true;
    if (refreshButton) refreshButton.disabled = true;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 4000);
    try {
      const capabilityRoot = `/${location.pathname.split('/')[1]}`;
      const logicalPath = location.pathname.slice(capabilityRoot.length) || '/';
      const logicalTarget = logicalPath + location.search;
      const response = await fetch(
        `${capabilityRoot}/dashboard/status?path=${encodeURIComponent(logicalTarget)}`,
        {cache: 'no-store', credentials: 'same-origin', signal: controller.signal}
      );
      if (!response.ok) throw new Error(`status check failed: ${response.status}`);
      const status = await response.json();
      setConnection('connected', 'Connected', status.checked_at);
      if (force || status.version !== version) {
        if (mode === 'replace') {
          await replaceLiveRegions();
          version = status.version;
          root.dataset.pageVersion = version;
        } else if (status.version !== version) {
          markChanged();
          version = status.version;
          root.dataset.pageVersion = version;
        }
      }
    } catch (_error) {
      setConnection('disconnected', 'Disconnected', 'retrying');
    } finally {
      window.clearTimeout(timeout);
      checking = false;
      if (refreshButton) refreshButton.disabled = false;
    }
  };

  const schedule = () => {
    window.clearInterval(timer);
    if (document.visibilityState === 'visible') {
      check();
      timer = window.setInterval(check, Number(root.dataset.pollSeconds) * 1000);
    }
  };

  refreshButton?.addEventListener('click', () => {
    if (mode === 'notice' && changeNotice && !changeNotice.hidden) {
      location.reload();
      return;
    }
    check({force: true});
  });
  document.addEventListener('visibilitychange', schedule);
  schedule();
})();
