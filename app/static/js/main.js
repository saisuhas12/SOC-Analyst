// SOC Sentinel XDR - Main Client Controller

document.addEventListener('DOMContentLoaded', function() {
    // 1. Auto dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert-cyber');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            // Smooth fade out using bootstrap utility
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // 2. Drag & Drop File Upload Handler
    const dropzone = document.getElementById('uploadDropzone');
    const fileInput = document.getElementById('fileInput');
    const selectedFilesDiv = document.getElementById('selectedFiles');

    if (dropzone && fileInput) {
        // Click to trigger hidden input file select
        dropzone.addEventListener('click', () => fileInput.click());

        // Visual feedback on drag actions
        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add('dragover');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove('dragover');
            }, false);
        });

        // Drop file event
        dropzone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            
            // Set inputs file list
            fileInput.files = files;
            updateFileList(files);
        });

        // Input change event
        fileInput.addEventListener('change', () => {
            updateFileList(fileInput.files);
        });
    }

    // Format selected file details
    function updateFileList(files) {
        if (!selectedFilesDiv) return;
        
        selectedFilesDiv.innerHTML = '';
        if (files.length === 0) {
            selectedFilesDiv.innerHTML = '<span class="text-muted">No files selected</span>';
            return;
        }

        const listGroup = document.createElement('div');
        listGroup.className = 'list-group list-group-flush bg-transparent mt-3 border border-secondary rounded';

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            const sizeKB = (file.size / 1024).toFixed(1);
            
            const item = document.createElement('div');
            item.className = 'list-group-item bg-dark text-light border-secondary d-flex justify-content-between align-items-center py-2';
            item.innerHTML = `
                <div>
                    <i class="bi bi-file-earmark-text text-success me-2"></i>
                    <span class="text-mono font-weight-bold">${file.name}</span>
                </div>
                <span class="badge bg-secondary text-mono">${sizeKB} KB</span>
            `;
            listGroup.appendChild(item);
        }
        selectedFilesDiv.appendChild(listGroup);
    }
});
