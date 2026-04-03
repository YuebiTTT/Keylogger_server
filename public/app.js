let ws;
let clients = [];
let currentClientId = null;
let currentLogs = [];

const wsStatus = document.getElementById('wsStatus');
const wsStatusText = document.getElementById('wsStatusText');
const clientsTable = document.getElementById('clientsTable');
const logsTable = document.getElementById('logsTable');
const logClientSelect = document.getElementById('logClientSelect');
const toast = document.getElementById('toast');

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}`);

    ws.onopen = () => {
        wsStatus.classList.add('connected');
        wsStatusText.textContent = '已连接';
        showToast('WebSocket 已连接', 'success');
    };

    ws.onclose = () => {
        wsStatus.classList.remove('connected');
        wsStatusText.textContent = '未连接';
        setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (error) => {
        console.error('WebSocket 错误:', error);
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
    };
}

function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'clients_list':
            clients = data.clients;
            updateClientsTable();
            updateLogClientSelect();
            break;

        case 'client_connected':
            showToast(`客户端 ${data.client.ip}:${data.client.port} 已连接`, 'success');
            break;

        case 'client_disconnected':
            showToast(`客户端 ${data.clientId} 已断开`, 'error');
            break;

        case 'client_offline':
            const offlineClient = clients.find(c => c.id === data.clientId);
            if (offlineClient) {
                offlineClient.status = 'offline';
                updateClientsTable();
            }
            break;

        case 'client_response':
            handleClientResponse(data.clientId, data.response);
            break;

        case 'command_result':
            if (data.result.success) {
                showToast('命令发送成功', 'success');
            } else {
                showToast(`命令发送失败: ${data.result.error}`, 'error');
            }
            break;

        case 'broadcast_result':
            const successCount = data.results.filter(r => r.success).length;
            showToast(`广播命令完成: ${successCount}/${data.results.length} 成功`, 'success');
            break;

        case 'scan_complete':
            document.getElementById('scanProgress').classList.remove('show');
            if (data.found.length > 0) {
                showToast(`扫描完成，发现 ${data.found.length} 个客户端`, 'success');
            } else {
                showToast('扫描完成，未发现客户端', 'error');
            }
            break;

        case 'connect_result':
            if (data.client) {
                showToast(`成功连接到 ${data.client.ip}:${data.client.port}`, 'success');
                hideModal('connectModal');
            } else {
                showToast('连接失败', 'error');
            }
            break;

        case 'disconnected':
            showToast('客户端已断开连接', 'success');
            break;

        case 'client_deleted':
            showToast(`客户端 ${data.clientId} 已删除`, 'success');
            // 更新客户端列表
            clients = clients.filter(c => c.id !== data.clientId);
            updateClientsTable();
            updateLogClientSelect();
            break;

        case 'error':
            showToast(`错误: ${data.message}`, 'error');
            break;
    }
}

function handleClientResponse(clientId, response) {
    if (response.status === 'ok') {
        const client = clients.find(c => c.id === clientId);
        if (client && response.data) {
            if (response.data.recording !== undefined) {
                client.recording = response.data.recording;
            }
            if (response.data.upload_enabled !== undefined) {
                client.uploadEnabled = response.data.upload_enabled;
            }
            updateClientsTable();
        }
    }
}

function updateClientsTable() {
    if (clients.length === 0) {
        clientsTable.innerHTML = '<tr><td colspan="7" class="empty-state">暂无客户端连接</td></tr>';
        return;
    }

    clientsTable.innerHTML = clients.map(client => `
        <tr>
            <td>${client.ip}</td>
            <td>${client.port}</td>
            <td><span class="status-badge ${client.status === 'online' ? 'status-online' : 'status-offline'}">${client.status === 'online' ? '在线' : '离线'}</span></td>
            <td><span class="status-badge ${client.recording ? 'status-recording' : 'status-paused'}">${client.recording ? '录制中' : '已暂停'}</span></td>
            <td><span class="status-badge ${client.uploadEnabled ? 'status-online' : 'status-offline'}">${client.uploadEnabled ? '启用' : '禁用'}</span></td>
            <td>${new Date(client.lastSeen).toLocaleString()}</td>
            <td class="action-btns">
                <button class="btn btn-primary btn-sm" onclick="showClientDetails('${client.id}')">详情</button>
                <button class="btn btn-danger btn-sm" onclick="disconnectClient('${client.id}')">断开</button>
                <button class="btn btn-danger btn-sm" onclick="deleteClient('${client.id}')">删除</button>
            </td>
        </tr>
    `).join('');
}

function updateLogClientSelect() {
    const currentValue = logClientSelect.value;
    logClientSelect.innerHTML = '<option value="">选择客户端</option>' +
        clients.map(client => `<option value="${client.id}">${client.ip}:${client.port}</option>`).join('');
    logClientSelect.value = currentValue;
}

function showConnectModal() {
    document.getElementById('connectModal').classList.add('show');
}

function showScanModal() {
    document.getElementById('scanModal').classList.add('show');
}

function hideModal(modalId) {
    document.getElementById(modalId).classList.remove('show');
}

function manualConnect() {
    const ip = document.getElementById('connectIp').value.trim();
    const port = parseInt(document.getElementById('connectPort').value);

    if (!ip) {
        showToast('请输入 IP 地址', 'error');
        return;
    }

    ws.send(JSON.stringify({
        type: 'manual_connect',
        ip,
        port
    }));
}

function scanNetwork() {
    const startIp = document.getElementById('scanStartIp').value.trim();
    const endIp = document.getElementById('scanEndIp').value.trim();
    const portsStr = document.getElementById('scanPorts').value.trim();

    if (!startIp || !endIp) {
        showToast('请输入起始和结束 IP', 'error');
        return;
    }

    const ports = portsStr.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));

    document.getElementById('scanProgress').classList.add('show');

    ws.send(JSON.stringify({
        type: 'scan_network',
        startIp,
        endIp,
        ports
    }));

    hideModal('scanModal');
}

function showClientDetails(clientId) {
    currentClientId = clientId;
    const client = clients.find(c => c.id === clientId);
    if (!client) return;

    document.getElementById('clientModalTitle').textContent = `客户端详情 - ${client.ip}:${client.port}`;
    
    document.getElementById('clientInfo').innerHTML = `
        <div class="form-group">
            <label>IP 地址</label>
            <input type="text" value="${client.ip}" readonly>
        </div>
        <div class="form-group">
            <label>端口</label>
            <input type="text" value="${client.port}" readonly>
        </div>
        <div class="form-group">
            <label>状态</label>
            <input type="text" value="${client.status === 'online' ? '在线' : '离线'}" readonly>
        </div>
        <div class="form-group">
            <label>录制状态</label>
            <input type="text" value="${client.recording ? '录制中' : '已暂停'}" readonly>
        </div>
        <div class="form-group">
            <label>上传状态</label>
            <input type="text" value="${client.uploadEnabled ? '启用' : '禁用'}" readonly>
        </div>
        <div class="form-group">
            <label>最后连接时间</label>
            <input type="text" value="${new Date(client.lastSeen).toLocaleString()}" readonly>
        </div>
    `;

    loadClientLogs(clientId);
    document.getElementById('clientModal').classList.add('show');
}

function sendCommand(action) {
    if (!currentClientId) return;

    const command = { action };
    
    if (action === 'set_server') {
        const host = document.getElementById('serverHost').value.trim();
        const port = parseInt(document.getElementById('serverPort').value);
        if (!host) {
            showToast('请输入服务器地址', 'error');
            return;
        }
        command.host = host;
        command.port = port;
    }

    ws.send(JSON.stringify({
        type: 'command',
        clientId: currentClientId,
        command
    }));
}

function setServer() {
    sendCommand('set_server');
}

function broadcastCommand(action) {
    ws.send(JSON.stringify({
        type: 'broadcast_command',
        command: { action }
    }));
}

function disconnectClient(clientId) {
    if (confirm('确定要断开此客户端吗？')) {
        ws.send(JSON.stringify({
            type: 'disconnect_client',
            clientId
        }));
    }
}

function deleteClient(clientId) {
    if (confirm('确定要删除此客户端吗？这将从已知客户端列表中移除它。')) {
        ws.send(JSON.stringify({
            type: 'delete_client',
            clientId
        }));
    }
}

async function loadClientLogs(clientId) {
    try {
        const response = await fetch(`/api/clients/${clientId}/logs`);
        const logs = await response.json();
        currentLogs = logs;
        updateLogsTable(logs);
    } catch (e) {
        document.getElementById('clientLogs').innerHTML = '<p class="empty-state">加载日志失败</p>';
    }
}

function updateLogsTable(logs) {
    const container = document.getElementById('clientLogs');
    
    if (logs.length === 0) {
        container.innerHTML = '<p class="empty-state">暂无日志文件</p>';
        return;
    }

    container.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>文件名</th>
                    <th>大小</th>
                    <th>上传时间</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody>
                ${logs.map(log => `
                    <tr>
                        <td>${log.filename}</td>
                        <td>${formatFileSize(log.size)}</td>
                        <td>${new Date(log.uploadTime).toLocaleString()}</td>
                        <td class="action-btns">
                            <button class="btn btn-primary btn-sm" onclick="viewLog('${log.filename}')">查看</button>
                            <button class="btn btn-success btn-sm" onclick="downloadLog('${log.filename}')">下载</button>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

async function viewLog(filename) {
    const clientId = logClientSelect.value || currentClientId;
    if (!clientId) {
        showToast('请先选择客户端', 'error');
        return;
    }

    try {
        const response = await fetch(`/api/clients/${clientId}/logs/${filename}`);
        const data = await response.json();
        
        document.getElementById('logModalTitle').textContent = `日志内容 - ${filename}`;
        document.getElementById('logContent').textContent = data.content;
        document.getElementById('logModal').classList.add('show');
    } catch (e) {
        showToast('加载日志失败', 'error');
    }
}

function downloadLog(filename) {
    const clientId = logClientSelect.value || currentClientId;
    if (!clientId) {
        showToast('请先选择客户端', 'error');
        return;
    }

    window.open(`/api/clients/${clientId}/logs/${filename}/download`, '_blank');
}

async function refreshLogs() {
    const clientId = logClientSelect.value;
    if (!clientId) {
        showToast('请先选择客户端', 'error');
        return;
    }

    try {
        const response = await fetch(`/api/clients/${clientId}/logs`);
        const logs = await response.json();
        currentLogs = logs;
        
        const searchTerm = document.getElementById('logSearch').value.toLowerCase();
        const filteredLogs = searchTerm 
            ? logs.filter(log => log.filename.toLowerCase().includes(searchTerm))
            : logs;
        
        updateMainLogsTable(filteredLogs, clientId);
    } catch (e) {
        showToast('刷新日志失败', 'error');
    }
}

function updateMainLogsTable(logs, clientId) {
    if (logs.length === 0) {
        logsTable.innerHTML = '<tr><td colspan="4" class="empty-state">暂无日志文件</td></tr>';
        return;
    }

    logsTable.innerHTML = logs.map(log => `
        <tr>
            <td>${log.filename}</td>
            <td>${formatFileSize(log.size)}</td>
            <td>${new Date(log.uploadTime).toLocaleString()}</td>
            <td class="action-btns">
                <button class="btn btn-primary btn-sm" onclick="viewLog('${log.filename}')">查看</button>
                <button class="btn btn-success btn-sm" onclick="downloadLog('${log.filename}')">下载</button>
            </td>
        </tr>
    `).join('');
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showToast(message, type = 'success') {
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function saveSettings() {
    showToast('设置已保存', 'success');
}

document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
        item.classList.add('active');
        
        const page = item.dataset.page;
        document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
        document.getElementById(page + 'Page').style.display = 'block';
    });
});

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        const tabGroup = tab.parentElement;
        tabGroup.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        const tabName = tab.dataset.tab;
        const tabContent = document.getElementById(tabName + 'Tab');
        tabContent.parentElement.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tabContent.classList.add('active');
    });
});

logClientSelect.addEventListener('change', refreshLogs);

document.getElementById('logSearch').addEventListener('input', (e) => {
    const searchTerm = e.target.value.toLowerCase();
    const filteredLogs = searchTerm 
        ? currentLogs.filter(log => log.filename.toLowerCase().includes(searchTerm))
        : currentLogs;
    updateMainLogsTable(filteredLogs, logClientSelect.value);
});

document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.remove('show');
        }
    });
});

connectWebSocket();

