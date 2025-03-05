# PenMate
<p>Toolset has its own sections of tools to perform specific actions. Here you can find all information about the toolset and what does it include. It has been developed to support my own work while performing penetration tests on virtual machines. It relies on already existing tools and includes custom implementations of some functionalities. The project is being supported as it is developed and integrated with the latest penetration testing tools over the next 2 years. It is intended to support repetitive processes that take too long to execute manually. A detailed description of each section and what tools they use is below:</p>
<h3>CommandAutomator</h3>
<p>Command automation tool is a function which records all commands terminated in linux bash terminal and converts them into bash file. When a sequence is fed into the program, all commands execute simultaneously in real time. It allows creating a script and adapt it to specific cases. It is possible to interact with other pentesting applications, as they also interact with the user thanks to bash.</p>
<p>To save your sequence type: <code>savesqnc example.sh</code> as input, where 'example' is your script name.</p>
<!---
screenshot
-->
<h3>NetworkRipper</h3>
<p>This automation kit is based on the use of the following tools:</p>
<ol>
  <li><a href="https://www.scapy.net">Scapy</a></li>
  <li>Second item</li>
  <li>Third item</li>
  <li>Fourth item</li>
</ol>
<h2>Installation:</h2>
<p>Toolset comes as a debian package. To install it properly use <code>dpkg</code>command:</p>
<pre><code>sudo dpkg -i pen-mate</code></pre>

