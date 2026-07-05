// Advanced Orchestration for UNIBEN Sync (Serverless Optimized)
async function triggerUnibenSync(btnId) {
    const btn = document.getElementById(btnId);
    const originalContent = btn.innerHTML;
    const csrf = document.querySelector('meta[name="csrf-token"]').content;

    // Optional UI elements for detailed progress
    const statusBox = document.getElementById('sync-status-box');
    const statusMsg = document.getElementById('sync-msg');
    const statusPct = document.getElementById('sync-pct');
    const progressBar = document.getElementById('sync-progress-bar');

    const confirmed = await showConfirm('Auto-Update Engine', 'This will initialize a high-fidelity sync with the UNIBEN academic registry. This process is orchestrated client-side in three stages (Faculties -> Departments -> Courses) to ensure stability in serverless environments. Proceed?');
    if (!confirmed) return;

    btn.disabled = true;
    btn.classList.add('opacity-50');
    if (statusBox) statusBox.classList.remove('hidden');
    showToast('Initializing architectural sync...', 'info');

    try {
        // STAGE 1: Discover Faculties
        const discMsg = 'Discovering faculties...';
        btn.innerHTML = `<svg class="animate-spin h-4 w-4 mr-2 inline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"/></svg> Discovering...`;
        if (statusMsg) statusMsg.innerText = discMsg;

        const discResp = await fetch('/admin/sync/discover-faculties', {
            method: 'POST',
            headers: { 'X-CSRFToken': csrf }
        });
        const discData = await discResp.json();

        if (!discData.success || !discData.faculties.length) {
            throw new Error(discData.message || 'No faculties discovered.');
        }

        const faculties = discData.faculties;
        let syncedDeptCount = 0;
        let syncedCourseCount = 0;

        // STAGE 2: Sequential Faculty/Dept Sync
        for (let i = 0; i < faculties.length; i++) {
            const f = faculties[i];
            const progress = Math.round(((i + 1) / faculties.length) * 50); // Stages 1 & 2 take up 50%
            const syncMsg = `Syncing departments: ${f.name}...`;

            btn.innerHTML = `<svg class="animate-spin h-4 w-4 mr-2 inline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"/></svg> Stage 2/3...`;

            if (statusMsg) statusMsg.innerText = syncMsg;
            if (statusPct) statusPct.innerText = progress + '%';
            if (progressBar) progressBar.style.width = progress + '%';

            const syncResp = await fetch('/admin/sync/faculty-departments', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrf
                },
                body: JSON.stringify(f)
            });
            const syncData = await syncResp.json();

            if (syncData.success && syncData.departments) {
                syncedDeptCount += syncData.count;

                // STAGE 3: Course Sync for each department in this faculty
                const depts = syncData.departments;
                for (let j = 0; j < depts.length; j++) {
                    const d = depts[j];
                    const courseSyncResp = await fetch('/admin/sync/department-courses', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': csrf
                        },
                        body: JSON.stringify({
                            f_code: f.code,
                            d_code: d.code
                        })
                    });
                    const courseData = await courseSyncResp.json();
                    if (courseData.success) syncedCourseCount += courseData.count;
                }
            }
        }

        if (statusMsg) statusMsg.innerText = 'Sync Complete';
        if (statusPct) statusPct.innerText = '100%';
        if (progressBar) progressBar.style.width = '100%';

        showToast(`Lattice Updated: ${faculties.length} Faculties, ${syncedDeptCount} Departments, ${syncedCourseCount} Courses synced.`, 'success');
        setTimeout(() => location.reload(), 2000);

    } catch (err) {
        showToast(`Sync Interrupted: ${err.message}`, 'error');
        console.error('Sync error', err);
    } finally {
        btn.disabled = false;
        btn.classList.remove('opacity-50');
        btn.innerHTML = originalContent;
    }
}
