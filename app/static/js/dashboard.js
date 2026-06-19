// SOC Sentinel XDR - Dashboard Visualization Controller

document.addEventListener('DOMContentLoaded', function() {
    // Cyber color palette variables
    const colors = {
        low: '#00e676',       // Neon Green
        medium: '#ffea00',    // Neon Amber
        high: '#ff9100',      // Neon Orange
        critical: '#ff1744',  // Neon Red
        blue: '#00b0ff',      // Neon Blue
        background: '#151c2c',
        border: 'rgba(255, 255, 255, 0.07)',
        grid: 'rgba(255, 255, 255, 0.04)',
        tooltipBg: 'rgba(11, 15, 25, 0.9)'
    };

    // Shared Chart.js options
    const baseOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: {
                    color: '#8b9bb4',
                    font: { family: 'Inter', size: 11 }
                }
            },
            tooltip: {
                backgroundColor: colors.tooltipBg,
                borderColor: 'rgba(255, 255, 255, 0.1)',
                borderWidth: 1,
                titleColor: '#fff',
                bodyColor: '#f5f6fa',
                titleFont: { family: 'Orbitron', size: 12 },
                bodyFont: { family: 'Inter', size: 12 },
                padding: 10,
                displayColors: true,
                boxWidth: 8,
                boxHeight: 8,
                boxPadding: 4
            }
        }
    };

    // Fetch metrics from backend API
    fetch('/api/chart-data')
        .then(response => response.json())
        .then(data => {
            initSeverityChart(data.severity);
            initTimelineChart(data.timeline);
            initCountriesChart(data.countries);
            initIPsChart(data.ips);
        })
        .catch(err => {
            console.error("Error loading SOC metrics data: ", err);
        });

    // 1. Severity Doughnut Chart
    function initSeverityChart(sevData) {
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: sevData.labels,
                datasets: [{
                    data: sevData.counts,
                    backgroundColor: [colors.low, colors.medium, colors.high, colors.critical],
                    borderColor: colors.background,
                    borderWidth: 2,
                    hoverOffset: 4
                }]
            },
            options: {
                ...baseOptions,
                cutout: '65%',
                plugins: {
                    ...baseOptions.plugins,
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#8b9bb4',
                            font: { family: 'Orbitron', size: 11 }
                        }
                    }
                }
            }
        });
    }

    // 2. Timeline Line Chart (Success vs. Failures over 7 Days)
    function initTimelineChart(timelineData) {
        const ctx = document.getElementById('timelineChart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: timelineData.labels,
                datasets: [
                    {
                        label: 'Successful Logins',
                        data: timelineData.success,
                        borderColor: colors.blue,
                        backgroundColor: 'rgba(0, 176, 255, 0.05)',
                        fill: true,
                        tension: 0.3,
                        borderWidth: 2,
                        pointBackgroundColor: colors.blue,
                        pointBorderColor: colors.background,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    },
                    {
                        label: 'Failed Logins (Threats)',
                        data: timelineData.failed,
                        borderColor: colors.critical,
                        backgroundColor: 'rgba(255, 23, 68, 0.05)',
                        fill: true,
                        tension: 0.3,
                        borderWidth: 2,
                        pointBackgroundColor: colors.critical,
                        pointBorderColor: colors.background,
                        pointRadius: 4,
                        pointHoverRadius: 6
                    }
                ]
            },
            options: {
                ...baseOptions,
                scales: {
                    x: {
                        grid: { color: colors.grid },
                        ticks: { color: '#8b9bb4', font: { family: 'Inter', size: 10 } }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: colors.grid },
                        ticks: { 
                            color: '#8b9bb4', 
                            font: { family: 'Inter', size: 10 },
                            stepSize: 1
                        }
                    }
                }
            }
        });
    }

    // 3. Top Attacking Countries Horizontal Bar Chart
    function initCountriesChart(countryData) {
        const ctx = document.getElementById('countriesChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: countryData.labels,
                datasets: [{
                    label: 'Failed Login Events',
                    data: countryData.counts,
                    backgroundColor: 'rgba(255, 145, 0, 0.65)', // High Amber-Orange
                    borderColor: colors.high,
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                ...baseOptions,
                indexAxis: 'y', // makes it horizontal
                plugins: {
                    ...baseOptions.plugins,
                    legend: { display: false }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: { color: colors.grid },
                        ticks: { 
                            color: '#8b9bb4', 
                            font: { family: 'Inter', size: 10 },
                            stepSize: 1
                        }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#8b9bb4', font: { family: 'Orbitron', size: 10 } }
                    }
                }
            }
        });
    }

    // 4. Top Attacking IPs Vertical Bar Chart
    function initIPsChart(ipData) {
        const ctx = document.getElementById('ipsChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ipData.labels,
                datasets: [{
                    label: 'Failed Logins',
                    data: ipData.counts,
                    backgroundColor: 'rgba(255, 23, 68, 0.65)', // Red Accent
                    borderColor: colors.critical,
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                ...baseOptions,
                plugins: {
                    ...baseOptions.plugins,
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: '#8b9bb4', font: { family: 'JetBrains Mono', size: 9 } }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: colors.grid },
                        ticks: { 
                            color: '#8b9bb4', 
                            font: { family: 'Inter', size: 10 },
                            stepSize: 1
                        }
                    }
                }
            }
        });
    }
});
