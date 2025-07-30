// Users Management JavaScript
let users = [];
let servers = [];

// Load data on page load
document.addEventListener('DOMContentLoaded', () => {
    loadUsers();
    loadServers();
    setupEventListeners();
});

function setupEventListeners() {
    // Protocol enable/disable toggles
    document.getElementById('enableWireGuard').addEventListener('change', toggleWireGuardConfig);
    document.getElementById('enableOpenVPN').addEventListener('change', toggleOpenVPNConfig);
    document.getElementById('ovpnAuthType').addEventListener('change', toggleOpenVPNAuthConfig);
    
    // Search functionality
    document.getElementById('userSearch').addEventListener('input', filterUsers);
    
    // Form submissions
    document.getElementById('createUserForm').addEventListener('submit', handleCreateUser);
    document.getElementById('editUserForm').addEventListener('submit', handleEditUser);
}

async function loadUsers() {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            window.location.href = '/';
            return;
        }

        const response = await fetch('/api/users', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            users = data.users;
            renderUsers();
            updateUserStats();
        } else {
            showError('Failed to load users');
        }
    } catch (error) {
        showError('Network error occurred');
    }
}

async function loadServers() {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch('/api/servers', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            servers = data.servers;
            populateServerSelects();
        }
    } catch (error) {
        console.error('Failed to load servers:', error);
    }
}

function populateServerSelects() {
    const wgServerSelect = document.getElementById('wgServer');
    const ovpnServerSelect = document.getElementById('ovpnServer');
    
    // Clear existing options
    wgServerSelect.innerHTML = '<option value="">Select Server</option>';
    ovpnServerSelect.innerHTML = '<option value="">Select Server</option>';
    
    // Add WireGuard servers
    servers.filter(s => s.protocol === 'wireguard').forEach(server => {
        const option = document.createElement('option');
        option.value = server.id;
        option.textContent = `${server.name} (${server.endpoint})`;
        wgServerSelect.appendChild(option);
    });
    
    // Add OpenVPN servers
    servers.filter(s => s.protocol === 'openvpn').forEach(server => {
        const option = document.createElement('option');
        option.value = server.id;
        option.textContent = `${server.name} (${server.endpoint})`;
        ovpnServerSelect.appendChild(option);
    });
}

function renderUsers() {
    const tbody = document.getElementById('usersTableBody');
    
    if (users.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center">
                    <div class="empty-state">
                        <i class="fas fa-users"></i>
                        <h3>No users found</h3>
                        <p>Create your first user to get started.</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = users.map(user => `
        <tr>
            <td>
                <div class="user-info">
                    <strong>${user.username}</strong>
                    <small>${user.user_id}</small>
                </div>
            </td>
            <td>${user.email}</td>
            <td><span class="badge badge-${getRoleBadgeClass(user.role)}">${user.role}</span></td>
            <td>
                <div class="protocol-badges">
                    ${user.enabled_protocols.map(protocol => 
                        `<span class="badge badge-info">${protocol}</span>`
                    ).join('')}
                </div>
            </td>
            <td><span class="badge badge-${getStatusBadgeClass(user.status)}">${user.status}</span></td>
            <td>
                <div class="combined-usage-info">
                    <div class="usage-summary">
                        <strong>${user.usage_stats.combined.total_used_gb.toFixed(2)} GB</strong>
                        <small>Total Used</small>
                    </div>
                    <div class="usage-limits">
                        <div class="limit-item">
                            <span>Daily: ${user.usage_stats.combined.daily_used_gb.toFixed(2)}/${user.usage_stats.combined.daily_limit_gb.toFixed(2)} GB</span>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${Math.min(user.usage_stats.combined.daily_percentage, 100)}%; background-color: ${getProgressColor(user.usage_stats.combined.daily_percentage)}"></div>
                            </div>
                        </div>
                        <div class="limit-item">
                            <span>Monthly: ${user.usage_stats.combined.monthly_used_gb.toFixed(2)}/${user.usage_stats.combined.monthly_limit_gb.toFixed(2)} GB</span>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${Math.min(user.usage_stats.combined.monthly_percentage, 100)}%; background-color: ${getProgressColor(user.usage_stats.combined.monthly_percentage)}"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </td>
            <td>
                <div class="protocol-breakdown">
                    ${Object.entries(user.usage_stats.protocols).map(([protocol, data]) => `
                        <div class="protocol-item">
                            <div class="protocol-header">
                                <span class="protocol-name">${protocol.toUpperCase()}</span>
                                <span class="protocol-usage">${data.total_used_gb.toFixed(2)} GB</span>
                            </div>
                            <div class="protocol-bar">
                                <div class="protocol-fill" style="width: ${data.percentage_of_total}%; background-color: ${data.color}"></div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </td>
            <td>${user.last_login ? formatDate(user.last_login) : 'Never'}</td>
            <td>
                <div class="action-buttons">
                    <button class="btn btn-sm btn-info" onclick="editUser('${user.user_id}')" title="Edit">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-success" onclick="downloadConfigs('${user.user_id}')" title="Download Configs">
                        <i class="fas fa-download"></i>
                    </button>
                    <button class="btn btn-sm btn-warning" onclick="resetUsage('${user.user_id}')" title="Reset Usage">
                        <i class="fas fa-redo"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteUser('${user.user_id}')" title="Delete">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
}

function updateUserStats() {
    const totalUsers = users.length;
    const wireguardUsers = users.filter(u => u.enabled_protocols.includes('wireguard')).length;
    const openvpnUsers = users.filter(u => u.enabled_protocols.includes('openvpn')).length;
    const activeUsers = users.filter(u => u.status === 'active').length;
    
    document.getElementById('totalUsers').textContent = totalUsers;
    document.getElementById('wireguardUsers').textContent = wireguardUsers;
    document.getElementById('openvpnUsers').textContent = openvpnUsers;
    document.getElementById('activeUsers').textContent = activeUsers;
}

function filterUsers() {
    const searchTerm = document.getElementById('userSearch').value.toLowerCase();
    const filteredUsers = users.filter(user => 
        user.username.toLowerCase().includes(searchTerm) ||
        user.email.toLowerCase().includes(searchTerm) ||
        user.enabled_protocols.some(p => p.toLowerCase().includes(searchTerm))
    );
    
    renderFilteredUsers(filteredUsers);
}

function renderFilteredUsers(filteredUsers) {
    const tbody = document.getElementById('usersTableBody');
    
    if (filteredUsers.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center">
                    <div class="empty-state">
                        <i class="fas fa-search"></i>
                        <h3>No users found</h3>
                        <p>Try adjusting your search terms.</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = filteredUsers.map(user => `
        <tr>
            <td>
                <div class="user-info">
                    <strong>${user.username}</strong>
                    <small>${user.user_id}</small>
                </div>
            </td>
            <td>${user.email}</td>
            <td><span class="badge badge-${getRoleBadgeClass(user.role)}">${user.role}</span></td>
            <td>
                <div class="protocol-badges">
                    ${user.enabled_protocols.map(protocol => 
                        `<span class="badge badge-info">${protocol}</span>`
                    ).join('')}
                </div>
            </td>
            <td><span class="badge badge-${getStatusBadgeClass(user.status)}">${user.status}</span></td>
            <td>
                <div class="combined-usage-info">
                    <div class="usage-summary">
                        <strong>${user.usage_stats.combined.total_used_gb.toFixed(2)} GB</strong>
                        <small>Total Used</small>
                    </div>
                    <div class="usage-limits">
                        <div class="limit-item">
                            <span>Daily: ${user.usage_stats.combined.daily_used_gb.toFixed(2)}/${user.usage_stats.combined.daily_limit_gb.toFixed(2)} GB</span>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${Math.min(user.usage_stats.combined.daily_percentage, 100)}%; background-color: ${getProgressColor(user.usage_stats.combined.daily_percentage)}"></div>
                            </div>
                        </div>
                        <div class="limit-item">
                            <span>Monthly: ${user.usage_stats.combined.monthly_used_gb.toFixed(2)}/${user.usage_stats.combined.monthly_limit_gb.toFixed(2)} GB</span>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${Math.min(user.usage_stats.combined.monthly_percentage, 100)}%; background-color: ${getProgressColor(user.usage_stats.combined.monthly_percentage)}"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </td>
            <td>
                <div class="protocol-breakdown">
                    ${Object.entries(user.usage_stats.protocols).map(([protocol, data]) => `
                        <div class="protocol-item">
                            <div class="protocol-header">
                                <span class="protocol-name">${protocol.toUpperCase()}</span>
                                <span class="protocol-usage">${data.total_used_gb.toFixed(2)} GB</span>
                            </div>
                            <div class="protocol-bar">
                                <div class="protocol-fill" style="width: ${data.percentage_of_total}%; background-color: ${data.color}"></div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </td>
            <td>${user.last_login ? formatDate(user.last_login) : 'Never'}</td>
            <td>
                <div class="action-buttons">
                    <button class="btn btn-sm btn-info" onclick="editUser('${user.user_id}')" title="Edit">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-success" onclick="downloadConfigs('${user.user_id}')" title="Download Configs">
                        <i class="fas fa-download"></i>
                    </button>
                    <button class="btn btn-sm btn-warning" onclick="resetUsage('${user.user_id}')" title="Reset Usage">
                        <i class="fas fa-redo"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteUser('${user.user_id}')" title="Delete">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
}

// Protocol configuration toggles
function toggleWireGuardConfig() {
    const enabled = document.getElementById('enableWireGuard').checked;
    document.getElementById('wireguardConfig').style.display = enabled ? 'block' : 'none';
}

function toggleOpenVPNConfig() {
    const enabled = document.getElementById('enableOpenVPN').checked;
    document.getElementById('openvpnConfig').style.display = enabled ? 'block' : 'none';
}

function toggleOpenVPNAuthConfig() {
    const authType = document.getElementById('ovpnAuthType').value;
    document.getElementById('ovpnUserPassConfig').style.display = 
        authType === 'username_password' ? 'block' : 'none';
}

// Modal functions
function openCreateUserModal() {
    document.getElementById('createUserModal').style.display = 'block';
    document.getElementById('createUserForm').reset();
    toggleWireGuardConfig();
    toggleOpenVPNConfig();
}

function closeCreateUserModal() {
    document.getElementById('createUserModal').style.display = 'none';
}

function closeEditUserModal() {
    document.getElementById('editUserModal').style.display = 'none';
}

// Form handlers
async function handleCreateUser(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const userData = {
        username: formData.get('username'),
        email: formData.get('email'),
        password: formData.get('password'),
        role: formData.get('role'),
        expire_date: formData.get('expireDate') ? new Date(formData.get('expireDate')).toISOString() : null,
        
        // COMBINED limits (total across all protocols)
        total_daily_limit_gb: parseFloat(formData.get('totalDailyLimit')) || 0,
        total_monthly_limit_gb: parseFloat(formData.get('totalMonthlyLimit')) || 0,
        
        // Protocol configurations (no individual limits)
        protocols: {}
    };
    
    // WireGuard configuration
    if (formData.get('enableWireGuard')) {
        userData.protocols.wireguard = {
            enabled: true,
            server_id: formData.get('wgServer'),
            allowed_ips: formData.get('wgAllowedIPs')
        };
    }
    
    // OpenVPN configuration
    if (formData.get('enableOpenVPN')) {
        userData.protocols.openvpn = {
            enabled: true,
            server_id: formData.get('ovpnServer'),
            auth_type: formData.get('ovpnAuthType')
        };
        
        if (formData.get('ovpnAuthType') === 'username_password') {
            userData.protocols.openvpn.username = formData.get('ovpnUsername');
            userData.protocols.openvpn.password = formData.get('ovpnPassword');
        }
    }
    
    try {
        const token = localStorage.getItem('token');
        const response = await fetch('/api/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(userData)
        });
        
        if (response.ok) {
            showNotification('User created successfully', 'success');
            closeCreateUserModal();
            loadUsers();
        } else {
            const errorData = await response.json();
            showError(errorData.detail || 'Failed to create user');
        }
    } catch (error) {
        showError('Network error occurred');
    }
}

async function handleEditUser(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const userId = formData.get('userId');
    const userData = {
        email: formData.get('email'),
        role: formData.get('role'),
        status: formData.get('status'),
        expire_date: formData.get('expireDate') ? new Date(formData.get('expireDate')).toISOString() : null
    };
    
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`/api/users/${userId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(userData)
        });
        
        if (response.ok) {
            showNotification('User updated successfully', 'success');
            closeEditUserModal();
            loadUsers();
        } else {
            const errorData = await response.json();
            showError(errorData.detail || 'Failed to update user');
        }
    } catch (error) {
        showError('Network error occurred');
    }
}

async function editUser(userId) {
    const user = users.find(u => u.user_id === userId);
    if (!user) return;
    
    // Populate form fields
    document.getElementById('editUserId').value = user.user_id;
    document.getElementById('editUsername').value = user.username;
    document.getElementById('editEmail').value = user.email;
    document.getElementById('editRole').value = user.role;
    document.getElementById('editStatus').value = user.status;
    document.getElementById('editExpireDate').value = user.expire_date ? 
        new Date(user.expire_date).toISOString().slice(0, 16) : '';
    
    // Load combined usage statistics
    renderCombinedUsage(user.usage_stats);
    
    // Load protocol usage breakdown
    renderProtocolUsageBreakdown(user.usage_stats);
    
    // Load protocol management
    await loadUserProtocols(userId);
    
    document.getElementById('editUserModal').style.display = 'block';
}

function renderCombinedUsage(usageStats) {
    const container = document.getElementById('editCombinedUsage');
    const combined = usageStats.combined;
    
    container.innerHTML = `
        <div class="combined-usage-grid">
            <div class="usage-card">
                <div class="usage-header">
                    <i class="fas fa-chart-pie"></i>
                    <h4>Total Usage</h4>
                </div>
                <div class="usage-value">${combined.total_used_gb.toFixed(2)} GB</div>
            </div>
            
            <div class="usage-card">
                <div class="usage-header">
                    <i class="fas fa-calendar-day"></i>
                    <h4>Daily Usage</h4>
                </div>
                <div class="usage-value">${combined.daily_used_gb.toFixed(2)} GB</div>
                <div class="usage-limit">of ${combined.daily_limit_gb.toFixed(2)} GB</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${Math.min(combined.daily_percentage, 100)}%; background-color: ${getProgressColor(combined.daily_percentage)}"></div>
                </div>
            </div>
            
            <div class="usage-card">
                <div class="usage-header">
                    <i class="fas fa-calendar-alt"></i>
                    <h4>Monthly Usage</h4>
                </div>
                <div class="usage-value">${combined.monthly_used_gb.toFixed(2)} GB</div>
                <div class="usage-limit">of ${combined.monthly_limit_gb.toFixed(2)} GB</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${Math.min(combined.monthly_percentage, 100)}%; background-color: ${getProgressColor(combined.monthly_percentage)}"></div>
                </div>
            </div>
        </div>
    `;
}

function renderProtocolUsageBreakdown(usageStats) {
    const container = document.getElementById('editProtocolUsage');
    const protocols = usageStats.protocols;
    
    if (Object.keys(protocols).length === 0) {
        container.innerHTML = '<p class="no-data">No protocols enabled</p>';
        return;
    }
    
    container.innerHTML = `
        <div class="protocol-breakdown-grid">
            ${Object.entries(protocols).map(([protocol, data]) => `
                <div class="protocol-card">
                    <div class="protocol-header">
                        <div class="protocol-icon" style="background-color: ${data.color}">
                            <i class="fas ${getProtocolIcon(protocol)}"></i>
                        </div>
                        <div class="protocol-info">
                            <h4>${protocol.toUpperCase()}</h4>
                            <span class="protocol-status ${data.is_active ? 'active' : 'inactive'}">
                                ${data.is_active ? 'Active' : 'Inactive'}
                            </span>
                        </div>
                    </div>
                    
                    <div class="protocol-usage-details">
                        <div class="usage-item">
                            <label>Total Used:</label>
                            <span>${data.total_used_gb.toFixed(2)} GB</span>
                        </div>
                        <div class="usage-item">
                            <label>Daily Used:</label>
                            <span>${data.daily_used_gb.toFixed(2)} GB</span>
                        </div>
                        <div class="usage-item">
                            <label>Monthly Used:</label>
                            <span>${data.monthly_used_gb.toFixed(2)} GB</span>
                        </div>
                        <div class="usage-item">
                            <label>% of Total:</label>
                            <span>${data.percentage_of_total.toFixed(1)}%</span>
                        </div>
                    </div>
                    
                    <div class="protocol-bar">
                        <div class="protocol-fill" style="width: ${data.percentage_of_total}%; background-color: ${data.color}"></div>
                    </div>
                    
                    <div class="protocol-meta">
                        <small>Server: ${data.server_id}</small>
                        <small>Connections: ${data.connection_count}</small>
                        ${data.last_connected ? `<small>Last: ${formatDate(data.last_connected)}</small>` : ''}
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

function getProtocolIcon(protocol) {
    const icons = {
        'wireguard': 'fa-wifi',
        'openvpn': 'fa-shield-alt',
        'shadowsocks': 'fa-cloud',
        'v2ray': 'fa-rocket',
        'trojan': 'fa-horse'
    };
    return icons[protocol] || 'fa-network-wired';
}

function getProgressColor(percentage) {
    if (percentage >= 90) return '#dc3545'; // Red
    if (percentage >= 75) return '#ffc107'; // Yellow
    return '#28a745'; // Green
}

async function loadUserProtocols(userId) {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`/api/users/${userId}/protocols`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            const protocols = await response.json();
            renderProtocolManagement(protocols);
        }
    } catch (error) {
        console.error('Failed to load protocols:', error);
    }
}

function renderProtocolManagement(protocols) {
    const container = document.getElementById('editProtocols');
    container.innerHTML = Object.entries(protocols).map(([protocol, data]) => `
        <div class="protocol-management-item">
            <div class="protocol-header">
                <div class="protocol-info">
                    <h4>${protocol.toUpperCase()}</h4>
                    <small>Server: ${data.server_id}</small>
                </div>
                <label class="switch">
                    <input type="checkbox" ${data.is_active ? 'checked' : ''} 
                           onchange="toggleProtocol('${protocol}', this.checked)">
                    <span class="slider"></span>
                </label>
            </div>
            <div class="protocol-details">
                <p><strong>Used:</strong> ${data.total_used_gb.toFixed(2)} GB</p>
                <p><strong>Last Connected:</strong> ${data.last_connected || 'Never'}</p>
                <p><strong>Connections:</strong> ${data.connection_count}</p>
            </div>
        </div>
    `).join('');
}

async function toggleProtocol(protocol, enabled) {
    const userId = document.getElementById('editUserId').value;
    
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`/api/users/${userId}/protocols/${protocol}`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ enabled })
        });
        
        if (response.ok) {
            showNotification(`${protocol.toUpperCase()} ${enabled ? 'enabled' : 'disabled'}`, 'success');
            loadUserProtocols(userId);
        } else {
            showError(`Failed to ${enabled ? 'enable' : 'disable'} ${protocol}`);
        }
    } catch (error) {
        showError('Network error occurred');
    }
}

async function downloadConfigs(userId) {
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`/api/users/${userId}/configs`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            const configs = await response.json();
            
            // Create zip file with all configs
            const zip = new JSZip();
            
            Object.entries(configs).forEach(([protocol, config]) => {
                zip.file(`${protocol}.conf`, config);
            });
            
            const blob = await zip.generateAsync({ type: 'blob' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = `vpn-configs-${userId}.zip`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            showNotification('Configuration files downloaded', 'success');
        } else {
            showError('Failed to download configurations');
        }
    } catch (error) {
        showError('Network error occurred');
    }
}

async function resetUsage(userId) {
    if (!confirm('Are you sure you want to reset usage statistics for this user?')) {
        return;
    }
    
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`/api/users/${userId}/reset-usage`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            showNotification('Usage statistics reset successfully', 'success');
            loadUsers();
        } else {
            showError('Failed to reset usage statistics');
        }
    } catch (error) {
        showError('Network error occurred');
    }
}

async function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
        return;
    }
    
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`/api/users/${userId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (response.ok) {
            showNotification('User deleted successfully', 'success');
            loadUsers();
        } else {
            showError('Failed to delete user');
        }
    } catch (error) {
        showError('Network error occurred');
    }
}

// Utility functions
function getRoleBadgeClass(role) {
    switch (role) {
        case 'admin': return 'danger';
        case 'support': return 'warning';
        default: return 'primary';
    }
}

function getStatusBadgeClass(status) {
    switch (status) {
        case 'active': return 'success';
        case 'suspended': return 'danger';
        case 'expired': return 'warning';
        default: return 'secondary';
    }
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function showError(message) {
    if (window.VPNPanel && window.VPNPanel.showNotification) {
        window.VPNPanel.showNotification(message, 'error');
    } else {
        alert(message);
    }
}

function showNotification(message, type) {
    if (window.VPNPanel && window.VPNPanel.showNotification) {
        window.VPNPanel.showNotification(message, type);
    } else {
        alert(message);
    }
} 