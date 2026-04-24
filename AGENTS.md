# BurpSuite Team Extension

BurpSuite plugin for real-time collaborative web app testing. Shares proxy requests, scope, and repeater/intruder payloads between team members.

## Build

```bash
mvn package
```
Output: `target/BurpSuiteCollaborationClient.jar` (fat JAR with dependencies)

## Install

Pre-built JAR: `build/jar/BurpSuiteCollaborationClient.jar`

Manual: Load `target/BurpSuiteCollaborationClient.jar` via BurpSuite Extender tab.

## Structure

- `src/burp/BurpExtender.java` — BurpSuite extension entry point
- `src/teamextension/` — Main UI and business logic
- `build/jar/` — Pre-built release JARs

## Server

Backend server is a separate Go project: `github.com/Static-Flow/BurpSuiteTeamServer` (not in this repo).

## Notes

- Java 14
- No tests in this repo
- No CI workflows