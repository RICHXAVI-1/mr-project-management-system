document.addEventListener("DOMContentLoaded", function () {
    const recordBtn = document.getElementById("recordBtn");
    const stopBtn = document.getElementById("stopBtn");
    const status = document.getElementById("voiceStatus");
    const playback = document.getElementById("lastPlayback");

    let mediaRecorder;
    let chunks = [];

    recordBtn.addEventListener("click", async function () {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            mediaRecorder = new MediaRecorder(stream);
            chunks = [];

            mediaRecorder.ondataavailable = e => chunks.push(e.data);

            mediaRecorder.onstart = () => {
                recordBtn.classList.add("d-none");
                stopBtn.classList.remove("d-none");
                status.textContent = "Recording...";
            };

            mediaRecorder.onstop = async () => {
                stopBtn.classList.add("d-none");
                recordBtn.classList.remove("d-none");
                status.textContent = "Uploading...";

                const blob = new Blob(chunks, { type: "audio/webm" });
                playback.src = URL.createObjectURL(blob);
                playback.style.display = "block";

                const fd = new FormData();
                fd.append("voice", blob, "voice_note.webm");

                try {
                    const res = await fetch("{{ url_for('upload_voice') }}", {
                        method: "POST",
                        body: fd
                    });
                    const data = await res.json();
                    if (res.ok) {
                        status.textContent = "Voice note sent!";
                        setTimeout(() => location.reload(), 800);
                    } else {
                        status.textContent = data.error || "Upload failed.";
                    }
                } catch (err) {
                    console.error("Upload error:", err);
                    status.textContent = "Error uploading voice note.";
                }
            };

            mediaRecorder.start();
        } catch (err) {
            alert("Microphone access denied.");
            console.error(err);
        }
    });

    stopBtn.addEventListener("click", function () {
        if (mediaRecorder && mediaRecorder.state === "recording") {
            mediaRecorder.stop();
        }
    });
});
