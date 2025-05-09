document.addEventListener('DOMContentLoaded', () => {
    const chatButton = document.getElementById('chat-button');
    const chatBox = document.getElementById('chat-box');
    const closeChat = document.getElementById('close-chat');
    const chatMessages = document.getElementById('chat-messages');
    const chatInput = document.getElementById('chat-input');
    const sendMessage = document.getElementById('send-message');

    if (!chatButton || !chatBox) return;

    let isChatOpen = false;
    let csrfToken = '';

    // Fetch CSRF token
    function fetchCsrfToken() {
        return fetch('/csrf-token', { credentials: 'include' })
            .then(res => res.json())
            .then(data => {
                csrfToken = data.csrfToken;
            })
            .catch(err => console.error('CSRF fetch error:', err));
    }

    // Toggle chatbox visibility
    chatButton.addEventListener('click', () => {
        isChatOpen = !isChatOpen;
        chatBox.classList.toggle('visible', isChatOpen);
        if (isChatOpen) {
            fetchMessages();
            startPolling();
        } else {
            stopPolling();
        }
    });

    closeChat.addEventListener('click', () => {
        isChatOpen = false;
        chatBox.classList.remove('visible');
        stopPolling();
    });

    // Send message
    sendMessage.addEventListener('click', async () => {
        const message = chatInput.value.trim();
        if (!message) return;

        try {
            await fetchCsrfToken();
            const response = await fetch('/send-message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message, csrfToken }),
                credentials: 'include'
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.error || 'Failed to send message');
            }

            chatInput.value = '';
            fetchMessages();
        } catch (err) {
            console.error('Send message error:', err);
            alert('Failed to send message: ' + err.message);
        }
    });

    // Fetch user messages
    function fetchMessages() {
        fetch('/user-messages', { credentials: 'include' })
            .then(response => {
                if (!response.ok) throw new Error('Failed to fetch messages');
                return response.json();
            })
            .then(messages => {
                chatMessages.innerHTML = '';
                messages.forEach(msg => {
                    const messageDiv = document.createElement('div');
                    messageDiv.className = 'chat-message';
                    messageDiv.innerHTML = DOMPurify.sanitize(`
                        <p><strong>You (${msg.user_email}):</strong> ${msg.message}</p>
                        <p><small>${new Date(msg.created_at).toLocaleString()}</small></p>
                        ${msg.response ? `<p><strong>Support:</strong> ${msg.response}</p>
                        <p><small>${new Date(msg.responded_at).toLocaleString()}</small></p>` : ''}
                    `);
                    chatMessages.appendChild(messageDiv);
                });
                chatMessages.scrollTop = chatMessages.scrollHeight;
            })
            .catch(err => {
                console.error('Messages fetch error:', err);
                chatMessages.innerHTML = '<p>Error loading messages.</p>';
            });
    }

    // Polling for new messages
    let pollingInterval;
    function startPolling() {
        pollingInterval = setInterval(fetchMessages, 10000); // Poll every 10 seconds
    }

    function stopPolling() {
        clearInterval(pollingInterval);
    }

    // Initialize
    fetchCsrfToken().then(fetchMessages);
});