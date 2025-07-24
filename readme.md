## Custom TCP protocol

### 📝 Project description
This project was created as a **semestral task** for a networking subject at our uni. I was asked to develop custom TCP-like protocol inserted into the UDP protocol. This required proper understanding of both **UDP and TCP protocols**. I chose Python for this project because it felt the most straightforward to work with. 
At first, I had no idea how the project would function—I couldn’t even imagine the *“magic”* of **transferring data** from my laptop to a friend’s. However, **signs of success** appeared quickly. Within just a few days, I had implemented the **basic functionality**, and from there I focused on fine-tuning the code to **improve stability** and **speed**.
After many hours of **testing** and **refining**, I was finally satisfied with the **core system**. I then had some fun experimenting with **CLI animations** - adding things like a **loading bar** while sending or receiving files, or notifications for peer disconnections.
Following several more weeks of polishing and testing, I **successfully built a system** capable of sending and receiving **text messages**, any type of **file**, and **system messages** - all with maximum stability and reliability.


### 🛠️ Tech stack
- **Programming language:** Python
- **Netwok management:** Socket programming (Python `socket` module)

### 🌱 Skills gained & problems overcomed
- Python
- CLI development
- Debugging and testing
- Socket programming
- TCP and UDP protocols
- Peer to Peer communication
- Port management
- Threading / Multiprocessing
- File I/O

### 📊 Preview
Click on this image to watch preview: <br>
[![Watch the video preview here](https://img.youtube.com/vi/RDbhX7eBqpQ/0.jpg)](https://www.youtube.com/watch?v=RDbhX7eBqpQ)


### ⚙️ How to run

## 1. Clone the Repository
```bash
clone the repo
cd path/to/repo
```

## 2. Create and activate Conda environment
```bash
conda create -n custom_tcp_env python=3.11
conda activate custom_tcp_env
```

## 3. Install requirements
```bash
pip install crcmod
```

## 4. Simulate connection in 2 terminals
```bash
python3 main.py
```

## 5. Get started
1. Select device 1 and device 2
2. Wait for handshake and sync
3. enter `help` to find out what you can do
