"""Fudan grade monitor — refactored package.

Modules:
- config: constants and environment-derived settings
- webvpn: WebVPN URL encoding + WebVPNSession (off-campus access)
- direct_session: DirectSession (on-campus access, no VPN)
- grade_api: GradeClient for grades, GPA stats, and ranking
- encrypt: AES-grade encrypted storage of grade snapshots
- emailer: QQ-mail notification
"""
