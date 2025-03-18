# PenMate
<p>Toolset has its own sections of tools to perform specific actions. Here you can find all information about the toolset and what does it include. It has been developed to support my own work while performing penetration tests on virtual machines. It relies on already existing tools and includes custom implementations of some functionalities. The project is being supported as it is developed and integrated with the latest penetration testing tools over the next 2 years. It is intended to support repetitive processes that take too long to execute manually. A detailed description of each section and what tools they use is below:</p>
<h3>CommandAutomator</h3>
<p>Command automation tool is a function which records all commands terminated in linux bash terminal and converts them into bash file. When a sequence is fed into the program, all commands execute simultaneously in real time. It allows creating a script and adapt it to specific cases. It is possible to interact with other pentesting applications, as they also interact with the user thanks to bash.</p>
<p>To save your sequence type: <code>savesqnc example.sh</code> as input, where 'example' is your script name.</p>

![Screenshot](Screenshots/automatorExample.png)

<p>The output file <code>example.sh</code> and <code>test.txt</code>(created by touch command) are stored in desired directory.</p>

![Screenshot](Screenshots/AutomatorFiles.png)
<h3>NetworkRipper</h3>
<p>This automation kit is based on the use of the following tools:</p>
<ol>
  <li><a href="https://www.scapy.net">Scapy</a></li>
  <li><a href="https://github.com/derv82/wifite?tab=readme-ov-file">Wifite</a></li>
  <li><a href="https://github.com/csshark/sdr-cap/tree/main">Custom Sniffer Light Driver (modified driver from SDR-CAP project)</a></li>
  <li><a href="https://nmap.org/">Nmap</a></li>
  <li><a href="https://www.bettercap.org/">Bettercap</a></li>
  <li><a href="">Custom Signal Spectrum Capture Tool</a></li>
</ol>
<p>AI agent-like interaction has been introduced. Your input does not have to be identical to the one displayed in the list of supported commands. NetworkRipper is the biggest module of all from PenMate and has a lot of feautures, in case it is hard to develop new original solution, tool automates some of the most common tedious processes executed manually and provides customization of running the comamnds. By veryfing user parameters tools adapts to them by recommending and executing best scripts configuration possible.</p>
<p>With NetworkRipper penetration testers have to enter the goal and the application gives possible solutions based on keywords (for more complex tasks, give as many keywords as possible). All executed commands are displayed, so user has whole access to what has been executed. Many custom C drivers and solutions has been introduced and are distributed as open-source.</p> 
<p>Example usage:</p>

![Screenshot](Screenshots/nripper.png)


<h2>Installation:</h2>
<p>Toolset comes as a debian package. To install it properly use <code>dpkg</code>command:</p>
<pre><code>sudo dpkg -i pen-mate</code></pre>

