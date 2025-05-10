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
        if (!message) {
            chatMessages.innerHTML += '<p class="error">Message cannot be empty</p>';
            return;
        }

        try {
            await fetchCsrfToken();
            const response = await fetch('/send-message', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
                body: JSON.stringify({ message }),
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
            chatMessages.innerHTML += DOMPurify.sanitize(`<p class="error">Failed to send message: ${err.message}</p>`);
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
                    let messageContent = `
                        <div class="message-type user-message">
                            <p><strong>You (${msg.user_email || 'Guest'}):</strong> ${DOMPurify.sanitize(msg.message)}</p>
                            <p><small>${new Date(msg.created_at).toLocaleString()}</small></p>
                        </div>
                    `;
                    if (msg.response) {
                        messageContent += `
                            <div class="message-type admin-message">
                                <p><strong>Support:</strong> ${DOMPurify.sanitize(msg.response)}</p>
                                <p><small>${new Date(msg.responded_at).toLocaleString()}</small></p>
                            </div>
                        `;
                    }
                    messageDiv.innerHTML = DOMPurify.sanitize(messageContent);
                    chatMessages.appendChild(messageDiv);
                });
                chatMessages.scrollTop = chatMessages.scrollHeight;
            })
            .catch(err => {
                console.error('Messages fetch error:', err);
                chatMessages.innerHTML = DOMPurify.sanitize('<p class="error">Error loading messages.</p>');
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