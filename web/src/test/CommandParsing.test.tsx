import { describe, it, expect } from 'vitest'

// ── Command Parsing Logic (extracted from SessionInteract.tsx) ──────────

/** Known commands for tab completion */
const KNOWN_COMMANDS = [
  'help', 'sleep', 'kill', 'upload', 'download', 'shell', 'powershell',
  'execute-assembly', 'inject', 'ps', 'ls', 'cd', 'pwd', 'cat', 'mkdir',
  'rm', 'cp', 'mv', 'whoami', 'env', 'netstat', 'ifconfig', 'arp',
  'screenshot', 'keylog', 'hashdump', 'mimikatz', 'token', 'pivot',
  'socks', 'portfwd', 'exit', 'tasks', 'clear',
]

/** Parse a command string into command name and arguments */
function parseCommand(input: string): { command: string; args: string } {
  const trimmed = input.trim()
  if (!trimmed) return { command: '', args: '' }
  const parts = trimmed.split(/\s+/)
  return {
    command: parts[0],
    args: parts.slice(1).join(' '),
  }
}

/** Find tab completion matches for a partial command */
function getCompletions(partial: string): string[] {
  if (!partial) return []
  return KNOWN_COMMANDS.filter((c) => c.startsWith(partial))
}

/** Check if a command is a local-only command (not sent to implant) */
function isLocalCommand(command: string): boolean {
  return ['help', 'clear', 'exit', 'tasks'].includes(command)
}

// ── Tests ───────────────────────────────────────────────────────────────

describe('Command Parsing', () => {
  describe('parseCommand', () => {
    it('parses a simple command with no arguments', () => {
      const result = parseCommand('whoami')
      expect(result).toEqual({ command: 'whoami', args: '' })
    })

    it('parses a command with a single argument', () => {
      const result = parseCommand('sleep 30')
      expect(result).toEqual({ command: 'sleep', args: '30' })
    })

    it('parses a command with multiple arguments', () => {
      const result = parseCommand('upload /local/path /remote/path')
      expect(result).toEqual({ command: 'upload', args: '/local/path /remote/path' })
    })

    it('handles leading and trailing whitespace', () => {
      const result = parseCommand('  shell whoami  ')
      expect(result).toEqual({ command: 'shell', args: 'whoami' })
    })

    it('handles multiple spaces between arguments', () => {
      const result = parseCommand('cd   C:\\Users\\Admin')
      expect(result).toEqual({ command: 'cd', args: 'C:\\Users\\Admin' })
    })

    it('returns empty for empty input', () => {
      expect(parseCommand('')).toEqual({ command: '', args: '' })
      expect(parseCommand('   ')).toEqual({ command: '', args: '' })
    })

    it('parses commands with special characters in arguments', () => {
      const result = parseCommand('shell net user admin P@ss$w0rd! /add')
      expect(result).toEqual({ command: 'shell', args: 'net user admin P@ss$w0rd! /add' })
    })

    it('parses powershell commands with pipes', () => {
      const result = parseCommand('powershell Get-Process | Where-Object {$_.CPU -gt 100}')
      expect(result).toEqual({
        command: 'powershell',
        args: 'Get-Process | Where-Object {$_.CPU -gt 100}',
      })
    })

    it('parses execute-assembly with a path and arguments', () => {
      const result = parseCommand('execute-assembly /opt/Rubeus.exe kerberoast')
      expect(result).toEqual({
        command: 'execute-assembly',
        args: '/opt/Rubeus.exe kerberoast',
      })
    })
  })

  describe('Tab Completion', () => {
    it('returns all commands matching a prefix', () => {
      const matches = getCompletions('s')
      expect(matches).toContain('sleep')
      expect(matches).toContain('shell')
      expect(matches).toContain('screenshot')
      expect(matches).toContain('socks')
      expect(matches).not.toContain('help')
    })

    it('returns single match for unique prefix', () => {
      const matches = getCompletions('who')
      expect(matches).toEqual(['whoami'])
    })

    it('returns exact command for full match', () => {
      const matches = getCompletions('help')
      expect(matches).toEqual(['help'])
    })

    it('returns empty array for no matches', () => {
      expect(getCompletions('zzz')).toEqual([])
    })

    it('returns empty for empty input', () => {
      expect(getCompletions('')).toEqual([])
    })

    it('matches hyphenated commands', () => {
      const matches = getCompletions('exec')
      expect(matches).toEqual(['execute-assembly'])
    })

    it('returns multiple matches for common prefixes', () => {
      const matches = getCompletions('p')
      expect(matches).toContain('powershell')
      expect(matches).toContain('ps')
      expect(matches).toContain('pwd')
      expect(matches).toContain('pivot')
      expect(matches).toContain('portfwd')
    })
  })

  describe('Local Commands', () => {
    it('identifies help as a local command', () => {
      expect(isLocalCommand('help')).toBe(true)
    })

    it('identifies clear as a local command', () => {
      expect(isLocalCommand('clear')).toBe(true)
    })

    it('identifies exit as a local command', () => {
      expect(isLocalCommand('exit')).toBe(true)
    })

    it('identifies tasks as a local command', () => {
      expect(isLocalCommand('tasks')).toBe(true)
    })

    it('does not flag remote commands as local', () => {
      expect(isLocalCommand('shell')).toBe(false)
      expect(isLocalCommand('sleep')).toBe(false)
      expect(isLocalCommand('whoami')).toBe(false)
      expect(isLocalCommand('upload')).toBe(false)
    })
  })

  describe('Known Commands', () => {
    it('contains all expected command categories', () => {
      // File system commands
      expect(KNOWN_COMMANDS).toContain('ls')
      expect(KNOWN_COMMANDS).toContain('cd')
      expect(KNOWN_COMMANDS).toContain('pwd')
      expect(KNOWN_COMMANDS).toContain('cat')
      expect(KNOWN_COMMANDS).toContain('mkdir')
      expect(KNOWN_COMMANDS).toContain('rm')
      expect(KNOWN_COMMANDS).toContain('cp')
      expect(KNOWN_COMMANDS).toContain('mv')

      // Network commands
      expect(KNOWN_COMMANDS).toContain('netstat')
      expect(KNOWN_COMMANDS).toContain('ifconfig')
      expect(KNOWN_COMMANDS).toContain('arp')

      // Post-exploitation commands
      expect(KNOWN_COMMANDS).toContain('screenshot')
      expect(KNOWN_COMMANDS).toContain('keylog')
      expect(KNOWN_COMMANDS).toContain('hashdump')
      expect(KNOWN_COMMANDS).toContain('mimikatz')

      // Pivoting commands
      expect(KNOWN_COMMANDS).toContain('pivot')
      expect(KNOWN_COMMANDS).toContain('socks')
      expect(KNOWN_COMMANDS).toContain('portfwd')
    })

    it('does not contain duplicates', () => {
      const unique = new Set(KNOWN_COMMANDS)
      expect(unique.size).toBe(KNOWN_COMMANDS.length)
    })
  })
})
