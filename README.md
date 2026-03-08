# 🎙 Voix — Voice + Text Chat

A real-time voice and text chat app built with Flask, Socket.IO, and WebRTC.

## Features

- 🔐 User registration and login with JWT tokens
- 💬 Real-time text messaging
- 🎤 Voice chat via WebRTC
- 🏠 Create, archive, and delete rooms
- 🔒 Password-protected private rooms
- 🔑 Join any room by name
- 🌙 Multiple themes: Dark, Light, AMOLED, Forest, Sunset
- 🌍 Multi-language support: Russian, English, Armenian
- ✍️ Typing indicators
- 🔊 Speaking indicators with voice level meter
- 📧 Email validation via DNS (MX records)

## Tech Stack

- **Backend:** Python, Flask, Flask-SocketIO
- **Frontend:** Vanilla JS, HTML, CSS
- **Database:** SQLite
- **Voice:** WebRTC + Metered TURN servers
- **Real-time:** Socket.IO

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/armen-marg/voix.git
cd voix
```

### 2. Install dependencies

```bash
pip install flask flask-socketio dnspython python-dotenv
```

### 3. Create `.env` file

```
METERED_USERNAME=your_username_here
METERED_API_KEY=your_api_key_here
```

> Get your free TURN credentials at [metered.ca](https://www.metered.ca)

### 4. Run the server

```bash
python server.py
```

### 5. Open in browser

```
http://localhost:8080
```

## Usage with friends

- Make sure your friend is on the same network or connected via VPN (e.g. Radmin VPN)
- Share your local IP address with your friend
- They open `http://your-ip:8080` in their browser
- Both join the same room — voice and chat will work automatically

## Project Structure

```
voix/
├── server.py          # Flask backend
├── .env               # Secret keys (not committed)
├── .env.example       # Template for .env
├── .gitignore
└── templates/
    └── index.html     # Frontend (single file)
```

## License

MIT
