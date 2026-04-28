<div align="center">

![Header](https://capsule-render.vercel.app/api?type=waving&color=0:060b18,50:0d1628,100:00e5ff&height=180&section=header&text=Issam%20Heli&fontSize=52&fontColor=ffffff&fontAlignY=38&desc=Cybersecurity%20Engineer%20·%20SOC%20Infrastructure%20·%20AI%20Agent%20Developer&descAlignY=58&descSize=16&descColor=00e5ff)

[![Typing SVG](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=16&duration=3000&pause=1000&color=00E5FF&center=true&vCenter=true&width=600&lines=Building+autonomous+SOC+platforms+with+local+AI;Wazuh+·+Suricata+·+Shuffle+·+TheHive+·+MISP;FastAPI+·+React+·+Docker+·+pgvector+·+Ollama;Blue+team+%7C+SOAR+automation+%7C+Threat+detection)](https://github.com/IssamHeli)

<br/>

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/issam-heli)
[![Portfolio](https://img.shields.io/badge/Portfolio-060b18?style=for-the-badge&logo=firefox&logoColor=00e5ff)](https://issamheli.github.io/Portfoliowebsite/)
[![GitHub](https://img.shields.io/badge/GitHub-060b18?style=for-the-badge&logo=github&logoColor=white)](https://github.com/IssamHeli)

</div>

---

## About Me

Security-focused engineer building autonomous SOC platforms and AI-powered threat detection tools. Currently completing a cybersecurity formation with a focus on **blue team operations**, **SOAR automation**, and **local LLM integration** — no cloud dependency, no data leaks.

```
📍 Agadir, Morocco
🎓 Cybersecurity Formation — Projet Fin de Formation
🔭 Currently building: NexusSOC — AI-powered autonomous SOC analyst
🧠 Focus: Blue team · SOAR · Threat intelligence · AI agents
🌐 Open to: Cybersecurity & SOC engineering opportunities
```

---

## Tech Stack

<table>
<tr>
<td valign="top" width="50%">

**Security & SOC**

![Wazuh](https://img.shields.io/badge/Wazuh-00ADD8?style=flat-square&logo=wazuh&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-EF4444?style=flat-square&logoColor=white)
![Arkime](https://img.shields.io/badge/Arkime-1E40AF?style=flat-square&logoColor=white)
![Zeek](https://img.shields.io/badge/Zeek-0EA5E9?style=flat-square&logoColor=white)
![Shuffle](https://img.shields.io/badge/Shuffle_SOAR-6366F1?style=flat-square&logoColor=white)
![TheHive](https://img.shields.io/badge/TheHive-F59E0B?style=flat-square&logoColor=white)
![MISP](https://img.shields.io/badge/MISP-DC2626?style=flat-square&logoColor=white)
![Cortex](https://img.shields.io/badge/Cortex-7C3AED?style=flat-square&logoColor=white)
![OpenCTI](https://img.shields.io/badge/OpenCTI-1D4ED8?style=flat-square&logoColor=white)

**Infrastructure & DevOps**

![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat-square&logo=linux&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white)
![Grafana](https://img.shields.io/badge/Grafana-F46800?style=flat-square&logo=grafana&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=flat-square&logo=redis&logoColor=white)

</td>
<td valign="top" width="50%">

**AI & Backend**

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-000000?style=flat-square&logoColor=white)
![pgvector](https://img.shields.io/badge/pgvector-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![asyncpg](https://img.shields.io/badge/asyncpg-3776AB?style=flat-square&logo=python&logoColor=white)

**Frontend**

![React](https://img.shields.io/badge/React-61DAFB?style=flat-square&logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-646CFF?style=flat-square&logo=vite&logoColor=white)

**Tools**

![Git](https://img.shields.io/badge/Git-F05032?style=flat-square&logo=git&logoColor=white)
![VS Code](https://img.shields.io/badge/VS_Code-007ACC?style=flat-square&logo=visualstudiocode&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-009639?style=flat-square&logo=nginx&logoColor=white)

</td>
</tr>
</table>

---

## Featured Project

### [NexusSOC](https://github.com/IssamHeli/NexusSOC) — AI-Powered SOC Platform

> Autonomous alert triage platform that integrates a full enterprise SOC tool stack with a local LLM — fully offline, zero cloud dependency.

```
 Wazuh (SIEM) · Suricata (IDS) · Arkime (Packet) · Zeek (Network)
                              │
                       Shuffle SOAR              ← orchestration & automation
                      ┌───────┴────────┐
                    MISP           Cortex          ← threat intel & enrichment
                  (IOC DB)      (VT + AbuseIPDB)
                    OpenCTI                        ← CTI observables
                      └───────┬────────┘
                           TheHive                 ← case management
                              │
                    NexusSOC AI Agent              ← autonomous TP/FP triage
               ┌──────────────┴──────────────┐
        Ollama (local LLM)    pgvector memory & skills
               └──────────────┬──────────────┘
             React Dashboard · Grafana · Discord Alerts
```

| Feature | Details |
|---|---|
| AI Triage | Local LLM classifies every alert as True Positive or False Positive |
| Self-learning | Analyst feedback updates skill confidence via EMA (α=0.15) |
| Vector memory | pgvector HNSW index retrieves similar past cases at analysis time |
| Simulation | 16 Shuffle pipeline scenarios across 5 threat groups (ransomware, APT, insider, web, DNS) |
| Response | Automated playbooks: block IP, quarantine endpoint, Discord rich embed alert |
| Privacy | Zero cloud dependency — all inference runs locally via Ollama |

---

## GitHub Stats

<div align="center">

![GitHub Stats](https://github-readme-stats.vercel.app/api?username=IssamHeli&show_icons=true&theme=dark&hide_border=true&bg_color=060b18&title_color=00e5ff&icon_color=00e5ff&text_color=dce8f8&border_radius=10)

![GitHub Streak](https://streak-stats.demolab.com?user=IssamHeli&theme=dark&hide_border=true&background=060b18&ring=00e5ff&fire=00e5ff&currStreakLabel=00e5ff&sideLabels=7a90b5&dates=7a90b5&border_radius=10)

![Top Languages](https://github-readme-stats.vercel.app/api/top-langs/?username=IssamHeli&layout=compact&theme=dark&hide_border=true&bg_color=060b18&title_color=00e5ff&text_color=dce8f8&border_radius=10)

</div>

---

<div align="center">

![Footer](https://capsule-render.vercel.app/api?type=waving&color=0:00e5ff,50:0d1628,100:060b18&height=100&section=footer)

</div>
