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

    // Create badge element
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.style.display = 'none';
    chatButton.appendChild(badge);

    // Create loading spinner
    const spinner = document.createElement('div');
    spinner.className = 'spinner';
    spinner.style.display = 'none';
    chatMessages.appendChild(spinner);

    // Create notification modal
    const modal = document.createElement('div');
    modal.className = 'notification-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <p id="modal-message"></p>
            <button id="modal-close" aria-label="Close notification">OK</button>
        </div>
    `;
    document.body.appendChild(modal);
    const modalClose = modal.querySelector('#modal-close');
    modalClose.addEventListener('click', () => {
        modal.style.display = 'none';
    });

    // Format timestamp
    function formatTimestamp(date) {
        const now = new Date();
        const diff = (now - date) / (1000 * 60 * 60 * 24);
        if (diff < 1 && date.toDateString() === now.toDateString()) {
            return `Today, ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
        } else if (diff < 2 && date.getDate() === now.getDate() - 1) {
            return `Yesterday, ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
        } else {
            return date.toLocaleDateString() + ', ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
    }

    // Fetch CSRF token
    function fetchCsrfToken() {
        return fetch('/csrf-token', { credentials: 'include' })
            .then(res => res.json())
            .then(data => {
                csrfToken = data.csrfToken;
            })
            .catch(err => console.error('CSRF fetch error:', err));
    }

    // Check for unread messages and update badge
    function updateUnreadBadge() {
        fetch('/user-messages', { credentials: 'include' })
            .then(response => {
                if (!response.ok) throw new Error('Failed to fetch messages');
                return response.json();
            })
            .then(messages => {
                const unreadCount = messages.filter(msg => msg.response && !msg.seen).length;
                badge.textContent = unreadCount;
                badge.style.display = unreadCount > 0 ? 'inline-block' : 'none';
                if (unreadCount > 0 && !isChatOpen) {
                    modal.querySelector('#modal-message').textContent = `You have ${unreadCount} new response${unreadCount > 1 ? 's' : ''} from support!`;
                    modal.style.display = 'block';
                }
            })
            .catch(err => console.error('Badge update error:', err));
    }

    // Toggle chatbox visibility
    chatButton.addEventListener('click', () => {
        isChatOpen = !isChatOpen;
        chatBox.classList.toggle('visible', isChatOpen);
        if (isChatOpen) {
            fetchMessages();
            markMessagesAsSeen();
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
            chatMessages.innerHTML += DOMPurify.sanitize('<p class="error">Message cannot be empty</p>');
            return;
        }

        spinner.style.display = 'block';
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
            chatMessages.innerHTML += DOMPurify.sanitize('<p class="success">Message sent!</p>');
            fetchMessages();
        } catch (err) {
            console.error('Send message error:', err);
            chatMessages.innerHTML += DOMPurify.sanitize(`<p class="error">Failed to send message: Network error, please try again.</p>`);
        } finally {
            spinner.style.display = 'none';
        }
    });

    // Fetch user messages
    function fetchMessages() {
        spinner.style.display = 'block';
        fetch('/user-messages', { credentials: 'include' })
            .then(response => {
                if (!response.ok) throw new Error('Failed to fetch messages');
                return response.json();
            })
            .then(messages => {
                chatMessages.innerHTML = '';
                let lastDate = null;
                messages.forEach(msg => {
                    const messageDate = new Date(msg.created_at).toDateString();
                    if (lastDate !== messageDate) {
                        const divider = document.createElement('div');
                        divider.className = 'date-divider';
                        divider.textContent = new Date(msg.created_at).toLocaleDateString();
                        chatMessages.appendChild(divider);
                        lastDate = messageDate;
                    }
                    const messageDiv = document.createElement('div');
                    messageDiv.className = `chat-message ${msg.response && !msg.seen ? 'new-message' : ''}`;
                    let messageContent = `
                        <div class="message-type user-message">
                            <p><strong>You (${msg.user_email || 'Guest'}):</strong> ${DOMPurify.sanitize(msg.message)}</p>
                            <p><small>${formatTimestamp(new Date(msg.created_at))}</small></p>
                        </div>
                    `;
                    if (msg.response) {
                        messageContent += `
                            <div class="message-type admin-message">
                                <p><strong>Support:</strong> ${DOMPurify.sanitize(msg.response)}</p>
                                <p><small>${formatTimestamp(new Date(msg.responded_at))}</small></p>
                            </div>
                        `;
                    }
                    messageDiv.innerHTML = DOMPurify.sanitize(messageContent);
                    chatMessages.appendChild(messageDiv);
                });
                chatMessages.scrollTop = chatMessages.scrollHeight;
                updateUnreadBadge();
            })
            .catch(err => {
                console.error('Messages fetch error:', err);
                chatMessages.innerHTML = DOMPurify.sanitize('<p class="error">Error loading messages: Network error, please try again.</p>');
            })
            .finally(() => {
                spinner.style.display = 'none';
            });
    }

    // Mark messages as seen
    function markMessagesAsSeen() {
        fetch('/mark-messages-seen', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            credentials: 'include'
        })
            .then(response => {
                if (!response.ok) throw new Error('Failed to mark messages as seen');
                updateUnreadBadge();
            })
            .catch(err => console.error('Mark seen error:', err));
    }

    // Polling for new messages
    let pollingInterval;
    function startPolling() {
        pollingInterval = setInterval(() => {
            fetchMessages();
            updateUnreadBadge();
        }, 10000); // Poll every 10 seconds
    }

    function stopPolling() {
        clearInterval(pollingInterval);
    }

    // Initialize
    fetchCsrfToken().then(() => {
        updateUnreadBadge();
        fetchMessages();
    });

    // Accessibility
    chatButton.setAttribute('aria-label', 'Open chat');
    sendMessage.setAttribute('aria-label', 'Send message');
    chatInput.setAttribute('aria-label', 'Type your message');
});