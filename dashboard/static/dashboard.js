'use strict';
const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const colors = ['#c43940', '#d09034', '#4b84b7', '#258968', '#a2aaa4'];
const imageColors = ['#147556', '#477db6', '#bc7049', '#a45470', '#9c9935', '#55a3a0'];
const byId = id => document.getElementById(id);
const number = value => new Intl.NumberFormat('en').format(value);
let trendChart, breakdownChart, currentData, currentArtifact, historyPage = 0, requestVersion = 0;
const pageSize = 10;
const formatTime = value => new Date(value).toLocaleString('en-GB', {timeZone: 'UTC', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit'});
const escapeText = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[character]));
const status = passed => `<span class="status ${passed ? '' : 'blocked'}"><span class="status-dot"></span>${passed ? 'Passed' : 'Blocked'}</span>`;
const icons = () => { if (window.lucide) lucide.createIcons(); };

function detailButton(scanId) {
  return `<button class="row-action" data-scan="${escapeText(scanId)}" title="View scan details" aria-label="View scan details"><i data-lucide="arrow-up-right"></i></button>`;
}

function drawCharts(data) {
  if (!window.Chart) throw new Error('Chart assets could not be loaded.');
  Chart.defaults.font.family = "'Trebuchet MS', Verdana, sans-serif";
  Chart.defaults.font.size = 9;
  Chart.defaults.color = '#819086';
  const grouped = new Map();
  data.history.forEach(scan => {
    if (!grouped.has(scan.image)) grouped.set(scan.image, []);
    grouped.get(scan.image).push({x: new Date(scan.scanned_at).getTime(), y: scan.pending});
  });
  if (trendChart) trendChart.destroy();
  trendChart = new Chart(byId('trend'), {
    type: 'line',
    data: {datasets: Array.from(grouped, ([label, points], index) => ({label, data: points, borderColor: imageColors[index % imageColors.length], backgroundColor: imageColors[index % imageColors.length], borderWidth: 2, pointRadius: points.length > 30 ? 1 : 3, pointHoverRadius: 5, tension: 0.15}))},
    options: {responsive: true, maintainAspectRatio: false, animation: false, parsing: false, plugins: {legend: {position: 'bottom', labels: {usePointStyle: true, pointStyle: 'circle', boxWidth: 5, padding: 14}}, tooltip: {callbacks: {title: items => formatTime(items[0].parsed.x), label: item => `${item.dataset.label}: ${number(item.parsed.y)}`}}}, scales: {x: {type: 'linear', grid: {display: false}, ticks: {maxTicksLimit: 5, callback: value => new Date(value).toLocaleDateString('en-GB', {timeZone: 'UTC', day: '2-digit', month: 'short'})}}, y: {beginAtZero: true, border: {display: false}, grid: {color: '#e7ede8'}, ticks: {precision: 0, maxTicksLimit: 5}}}}
  });
  if (breakdownChart) breakdownChart.destroy();
  const selected = byId('severity').value;
  const values = levels.map(level => selected && selected !== level ? 0 : data.summary[level]);
  breakdownChart = new Chart(byId('breakdown'), {type: 'doughnut', data: {labels: levels, datasets: [{data: values, backgroundColor: colors, borderWidth: 3, borderColor: '#f5f7f5', hoverOffset: 3}]}, options: {responsive: true, maintainAspectRatio: false, cutout: '76%', animation: false, plugins: {legend: {display: false}}}});
  byId('severity-legend').innerHTML = levels.map((level, index) => `<div class="legend-row"><span class="swatch severity-${level.toLowerCase()}"></span>${level.charAt(0) + level.slice(1).toLowerCase()}<strong>${number(values[index])}</strong></div>`).join('');
}

function renderHistory() {
  const scans = currentData.history.slice().reverse();
  historyPage = Math.max(0, Math.min(historyPage, Math.ceil(scans.length / pageSize) - 1));
  const offset = historyPage * pageSize;
  byId('history-body').innerHTML = scans.slice(offset, offset + pageSize).map(scan => `<tr><td class="scan-id">${escapeText(scan.scan_id.slice(0, 8))}</td><td class="image-name">${escapeText(scan.image)}</td><td>${formatTime(scan.scanned_at)}</td><td>${number(scan.pending)}</td><td>${number(scan.found)}${scan.baseline ? ' *' : ''}</td><td class="resolved-number">${number(scan.resolved)}</td><td>${status(scan.passed)}</td><td>${detailButton(scan.scan_id)}</td></tr>`).join('');
  byId('history-count').textContent = `${offset + 1}-${Math.min(offset + pageSize, scans.length)} of ${scans.length}`;
  byId('previous').disabled = historyPage === 0;
  byId('next').disabled = offset + pageSize >= scans.length;
  icons();
}

async function load() {
  const version = ++requestVersion;
  byId('results').setAttribute('aria-busy', 'true');
  byId('error').hidden = true;
  byId('refresh').disabled = true;
  const params = new URLSearchParams();
  ['image', 'severity'].forEach(key => { if (byId(key).value) params.set(key, byId(key).value); });
  if (byId('start').value) params.set('start', byId('start').value + 'T00:00:00Z');
  if (byId('end').value) params.set('end', byId('end').value + 'T23:59:59.999999Z');
  try {
    const response = await fetch('/api/overview?' + params);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not load scan history.');
    if (version !== requestVersion) return;
    currentData = data;
    const selected = byId('image').value;
    byId('image').replaceChildren(new Option('All images', ''), ...data.images.map(image => new Option(image, image)));
    byId('image').value = selected;
    byId('connection-label').textContent = 'Connected';
    byId('results').hidden = !data.latest.length;
    byId('empty').hidden = !!data.latest.length;
    byId('empty-message').textContent = data.images.length ? 'No matching scans.' : 'No stored scan artifacts.';
    byId('empty-reset').hidden = !data.images.length;
    byId('updated').textContent = data.latest.length ? `${data.latest.length} images monitored / Latest scan ${formatTime(data.history[data.history.length - 1].scanned_at)} UTC` : 'No scan selected';
    if (!data.latest.length) return;
    ['pending', 'blocking', 'resolved', 'suppressed'].forEach(key => { byId('stat-' + key).textContent = number(data.totals[key]); });
    byId('blocked-images').textContent = `${data.totals.blocked_images} of ${data.totals.images} images blocked`;
    byId('image-count').textContent = number(data.totals.images);
    byId('inventory-body').innerHTML = data.latest.map(scan => `<tr><td class="image-name" title="${escapeText(scan.image)}"><i class="image-icon" data-lucide="container"></i>${escapeText(scan.image)}</td><td>${status(scan.passed)}</td><td class="number-critical">${number(scan.summary.CRITICAL)}</td><td class="number-high">${number(scan.summary.HIGH)}</td><td>${number(scan.pending)}</td><td class="resolved-number">${number(scan.resolved)}</td><td>${formatTime(scan.scanned_at)}</td><td>${detailButton(scan.scan_id)}</td></tr>`).join('');
    drawCharts(data);
    renderHistory();
  } catch (error) {
    if (version !== requestVersion) return;
    byId('error').textContent = error.message;
    byId('error').hidden = false;
    byId('connection-label').textContent = 'Unavailable';
  } finally {
    if (version === requestVersion) { byId('results').setAttribute('aria-busy', 'false'); byId('refresh').disabled = false; }
  }
}

function renderDetail() {
  const suppressed = byId('show-suppressed').checked;
  const filter = byId('severity').value;
  const findings = (suppressed ? currentArtifact.suppressed_findings || [] : currentArtifact.findings).filter(item => !filter || item.severity === filter);
  findings.sort((first, second) => levels.indexOf(first.severity) - levels.indexOf(second.severity));
  byId('detail-body').innerHTML = findings.length ? findings.slice(0, 500).map(finding => `<tr><td><span class="severity-text severity-text-${escapeText(finding.severity.toLowerCase())}">${escapeText(finding.severity)}</span></td><td>${escapeText(finding.id)}</td><td>${escapeText(finding.pkg)}</td><td>${escapeText(finding.installed)}</td><td>${escapeText(suppressed ? `${finding.exception.reason} (until ${finding.exception.expires})` : finding.fixed || 'No fix available')}</td></tr>`).join('') : '<tr><td colspan="5">No matching findings</td></tr>';
  byId('detail-limit').textContent = findings.length > 500 ? `Showing 500 of ${number(findings.length)} findings. Full data is included in the JSON download.` : `${number(findings.length)} findings`;
}

async function openDetail(scanId) {
  try {
    const response = await fetch('/api/scans/' + encodeURIComponent(scanId));
    if (!response.ok) throw new Error('Scan artifact could not be loaded.');
    currentArtifact = await response.json();
    byId('detail-title').textContent = currentArtifact.image;
    byId('detail-meta').textContent = `${currentArtifact.scan_id} / ${formatTime(currentArtifact.scanned_at)} UTC`;
    byId('detail-summary').innerHTML = `${status(currentArtifact.policy.passed)}<span>Threshold: ${escapeText(currentArtifact.policy.fail_on)}</span><span>Blocking: ${number(currentArtifact.policy.blocking_findings)}</span><span>Exceptions: ${number((currentArtifact.suppressed_findings || []).length)}</span>`;
    byId('show-suppressed').checked = false;
    renderDetail();
    byId('scan-dialog').showModal();
  } catch (error) { byId('error').textContent = error.message; byId('error').hidden = false; }
}

byId('filters').addEventListener('change', () => { historyPage = 0; load(); });
byId('filters').addEventListener('submit', event => event.preventDefault());
byId('filters').addEventListener('reset', () => { historyPage = 0; setTimeout(load, 0); });
byId('empty-reset').addEventListener('click', () => byId('filters').reset());
byId('refresh').addEventListener('click', load);
byId('previous').addEventListener('click', () => { historyPage--; renderHistory(); });
byId('next').addEventListener('click', () => { historyPage++; renderHistory(); });
document.addEventListener('click', event => { const button = event.target.closest('[data-scan]'); if (button) openDetail(button.dataset.scan); });
byId('close-dialog').addEventListener('click', () => byId('scan-dialog').close());
byId('show-suppressed').addEventListener('change', renderDetail);
byId('download').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([JSON.stringify(currentArtifact, null, 2)], {type: 'application/json'}));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = `scan-${currentArtifact.scan_id.replace(/[^a-zA-Z0-9-]/g, '_')}.json`; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
icons();
load();
const sharedScan = new URLSearchParams(location.search).get('scan');
if (sharedScan) openDetail(sharedScan);