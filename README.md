# torchat

Private chat with anyone in the world. **End-to-end encrypted. No servers. No browser.**
Text, photos and documents all travel through the same encrypted channel, directly between you and your friend over Tor.

## Quick start (3 steps)

## Which devices

| Device | How |
|---|---|
| **Linux** | `pip3 install -r requirements.txt` |
|           | `chmod +x setup.sh start.sh` |
|           | `./setup.sh` |
|           | `./start.sh` |
|           | **For GUI** `python3 start-gui.py` |
 

The two people can use different kinds of devices (for example Android and Linux).

## Pairing codes

* The code is 8 ordinary words, e.g. `few lawn turkey divide detect undo build desk`. Capitals, spaces and dashes don't matter, and the first 4 letters of each word are enough.
* The last word is a checksum, so a typo is caught instantly with a clear message.
* The code works **once** and only while the host's window stays open. If the host restarts, they get a **new** code - ask for the newest one.
* Tell the code to **one** person only. Anyone who knows it can join before your friend does - that is exactly what the safety-code check is for.
* Optional: add an **extra passphrase** that you agree on over a *different* route than the code. Both of you must enter the same one.

## The safety code (important)

After connecting, both screens show a short code like `4872 46de 93b9 c552 8925`. Read yours to your friend **by phone or in person (not in this chat)** and have them read theirs. If they are identical, nobody is in the middle. If they differ, click *They don't match* and start again.

## Sending photos and documents

* **Window:** *Send file...* button. **Text screen:** `/send ~/Pictures/cat.jpg`.
* Up to 50 MB per file. Every file is checked for damage and tampering.
* Photos (JPEG/PNG) have location, camera and other hidden details removed before sending. Documents (PDF, Word, ...) are sent unchanged and can contain the author's name or location - they are marked with a note.
* Received files wait in a private temporary folder. Click **Save...** (or `/save 1`) to keep one. **Nothing is opened automatically.** Program-type files (`.exe`, `.apk`, `.sh`, ...) get a warning.
* Everything in the temporary folder is wiped when you close the app.

## Settings (`torchat.conf`)

```
INTERFACE=auto        # auto, gui or text
TOR_CACHE=1           # 1 = faster starts by reusing Tor's public network list; 0 = keep nothing on disk
FIREWALL_80_443=0     # 1 = for networks that only allow web traffic (some schools/offices)
# BRIDGES_FILE=~/bridges.txt
```

## If it won't connect

Run **`python3 torchat.py --selftest`** - it starts a host and a guest on your own device and tells you which step fails.

* **"Tor is stuck at N%"** - your network blocks Tor, or the date/time is wrong. Turn on automatic time. Try another Wi-Fi, mobile data or a VPN.
* **Still blocked?** Get *bridges* from <https://bridges.torproject.org>, save the lines in a text file, install `obfs4proxy` (or `lyrebird`) - Termux: `pkg install obfs4proxy`, Debian/Ubuntu: `sudo apt install obfs4proxy` - and set `BRIDGES_FILE=` in `torchat.conf`.
* **"Host not found" / stays on "searching"** - the host must start first and keep their window open. Every restart makes a **new** code. After the host's Tor is ready it can take up to a minute for the code to become reachable.
* More detail: `python3 torchat.py --debug` prints Tor's log in the terminal.

## What protects you

* **Tor onion service:** works through any router or firewall, hides both IP addresses, and no server ever sees or stores anything.
* **The code is the key:** the 8 words are stretched (scrypt) into the onion address, an authorization key and a handshake secret, so only someone with the code can find or enter the chat.
* **Fresh keys for every message:** X25519 key exchange + Signal-style Double Ratchet + ChaCha20-Poly1305. Stolen keys can't read past messages and the chat heals itself afterwards.
* **No web server, no open port:** the app is a window or terminal plus a private socket to Tor.
* **Private by default:** nothing is saved except Tor's *public* network list (switch off with `TOR_CACHE=0`). Chats are never written to disk.

## Honest limits

* One-to-one chat only; both people must be online at the same time (there is no server to hold messages).
* It has not had a professional security audit. For life-or-death situations use a tool with a long public track record.
* No app can protect a phone or computer that is already infected, or stop someone looking over your shoulder.
* The very first start is slower while Tor builds its network list; later starts are faster.
* Fully offline/instant delivery, group chats and iPhone are not supported.
