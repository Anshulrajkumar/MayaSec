let currentPage = 1;
let totalPages = 1;
let isLoading = false;

// DOM elements
const dataTable = document.getElementById('data-tbody');
const searchInput = document.getElementById('search-input');
const threatFilter = document.getElementById('threat-filter');
const resultFilter = document.getElementById('result-filter');
const refreshBtn = document.getElementById('refresh-btn');
const prevBtn = document.getElementById('prev-btn');
const nextBtn = document.getElementById('next-btn');
const pageInfo = document.getElementById('page-info');
const loading = document.getElementById('loading');
const recentActivity = document.getElementById('recent-activity');
const totalEntries = document.getElementById('total-entries');

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    loadData();
    loadStats();
    setupEventListeners();
});

function setupEventListeners() {
    // Search input with debounce
    let searchTimeout;
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            currentPage = 1;
            loadData();
        }, 300);
    });

    // Filter changes
    threatFilter.addEventListener('change', function() {
        currentPage = 1;
        loadData();
    });

    resultFilter.addEventListener('change', function() {
        currentPage = 1;
        loadData();
    });

    // Pagination
    prevBtn.addEventListener('click', function() {
        if (currentPage > 1) {
            currentPage--;
            loadData();
        }
    });

    nextBtn.addEventListener('click', function() {
        if (currentPage < totalPages) {
            currentPage++;
            loadData();
        }
    });

    // Refresh button
    refreshBtn.addEventListener('click', function() {
        loadData();
        loadStats();
    });
}

async function loadData() {
    if (isLoading) return;
    
    isLoading = true;
    showLoading(true);
    
    try {
        const params = new URLSearchParams({
            page: currentPage,
            per_page: 10,
            search: searchInput.value,
            threat_level: threatFilter.value,
            attempt_result: resultFilter.value
        });

        const response = await fetch(`/api/data?${params}`);
        const data = await response.json();

        renderTable(data.data);
        updatePagination(data);
        
    } catch (error) {
        console.error('Error loading data:', error);
        dataTable.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #ff4757;">Error loading data</td></tr>';
    } finally {
        isLoading = false;
        showLoading(false);
    }
}

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        recentActivity.textContent = stats.recent_activity;
        
        // Calculate total from result stats
        const total = stats.result_stats.reduce((sum, stat) => sum + stat.count, 0);
        totalEntries.textContent = total;
        
    } catch (error) {
        console.error('Error loading stats:', error);
        recentActivity.textContent = 'Error';
        totalEntries.textContent = 'Error';
    }
}

function renderTable(data) {
    if (data.length === 0) {
        dataTable.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #bbb;">No data found</td></tr>';
        return;
    }

    const rows = data.map(row => `
        <tr>
            <td>${row.id}</td>
            <td>${row.ip_address}</td>
            <td>${row.username}</td>
            <td title="${row.password_hash}">${row.password_hash}</td>
            <td title="${row.user_agent}">${row.user_agent}</td>
            <td>${formatTimestamp(row.timestamp)}</td>
            <td class="attempt-${row.attempt_result.toLowerCase()}">${row.attempt_result}</td>
            <td><span class="threat-${row.threat_level.toLowerCase()}">${row.threat_level}</span></td>
        </tr>
    `).join('');

    dataTable.innerHTML = rows;
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function updatePagination(data) {
    currentPage = data.page;
    totalPages = data.total_pages;
    
    pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
    
    prevBtn.disabled = currentPage <= 1;
    nextBtn.disabled = currentPage >= totalPages;
}

function showLoading(show) {
    if (show) {
        loading.classList.add('show');
    } else {
        loading.classList.remove('show');
    }
}
