# CALDERA&trade; Pathfinder

## Overview
Pathfinder is a [CALDERA](https://github.com/mitre/caldera) plugin developed by the Center for Threat-Informed Defense. Pathfinder extends CALDERA's functionality to support automated ingestion of network scanning tool output. By intelligently integrating scan data with an automated adversary emulation platform, Pathfinder will demonstrate how an adversary might use vulnerabilities in an environment to achieve their goals, highlighting a path through a network, and showing the real impact of a vulnerability for CALDERA to analyze and execute against. 

Pathfinder extends CALDERA to do the following:
1. Run a scan of a target network or system
2. Upload the scan results to a running instance of CALDERA
3. Use the ingested results to draw out potential attack paths CALDERA could notionally take
4. Create workflows so that CALDERA can follow the actual attack paths and execute a real attack

More information is provided under [docs](https://github.com/center-for-threat-informed-defense/caldera_pathfinder/tree/master/docs)

## Tutorial Video

<div align="left">
      <a href="https://www.youtube.com/watch?v=gQRWkHFRG-s">
         <img src="https://img.youtube.com/vi/gQRWkHFRG-s/0.jpg" style="width:100%;">
      </a>
</div>

## Screenshot

![plugin home](docs/pathfinder.jpg)

###### map vulnerabilities. plan attacks.

## Getting Started

If you want to run scans with nmap directly with the pathfinder plugin make sure to install nmap on your system

Install CALDERA (if you don't have it already) and clone down the pathfinder repo into the `caldera/plugins` folder with this command:

`git clone https://github.com/center-for-threat-informed-defense/caldera_pathfinder.git pathfinder --recursive`

Go into `plugins/pathfinder` and run `pip install -r requirements.txt` to install dependencies, and note that you should have nmap installed already.

After that add `pathfinder` to enabled plugins list in the caldera conf file for your environment and you are set to start scanning and path finding!

## Questions and Feedback

Please submit issues for any technical questions/concerns or contact ctid@mitre-engenuity.org directly for more general inquiries.

Also see the guidance for contributors if are interested in [contributing.](https://github.com/center-for-threat-informed-defense/caldera_pathfinder/blob/master/CONTRIBUTING.md)


## Liability / Responsible Usage

This content is only to be used with appropriate prior, explicit authorization for the purposes of assessing security posture and/or research.

## Notice

Copyright 2020 MITRE Engenuity. Approved for public release. Document number CT0007

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
