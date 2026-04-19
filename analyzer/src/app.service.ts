import { Injectable } from '@nestjs/common';
import * as os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
// @ts-ignore
import nmap from 'node-nmap';

interface DeviceInfo {
  ip: string;
  mac: string | null;
  hostname?: string | null;
  source: 'arp' | 'nmap' | 'merged';
  details?: any;
}

@Injectable()
export class AppService {
  private knownDevices: string[] = [];

  private async getArpTable(): Promise<DeviceInfo[]> {
    const execAsync = promisify(exec);
    try {
      const { stdout } = await execAsync('arp -a');
      const lines = stdout.split('\n');
      const devices: DeviceInfo[] = [];
      for (const line of lines) {
        const match = line.match(/\? \(([^)]+)\) at ([0-9a-f:]+) on ([^ ]+)/);
        if (match && match[2] !== '(incomplete)' && match[2] !== 'ff:ff:ff:ff:ff:ff') {
          devices.push({
            ip: match[1],
            mac: match[2].toLowerCase(),
            hostname: null,
            source: 'arp',
          });
        }
      }
      return devices;
    } catch (error) {
      console.error('Error getting ARP table:', error);
      return [];
    }
  }

  private getLocalSubnet(): string {
    const interfaces = os.networkInterfaces();
    for (const ifaceList of Object.values(interfaces)) {
      if (!ifaceList) continue;
      for (const addr of ifaceList) {
        if (addr.family === 'IPv4' && !addr.internal) {
          const ipParts = addr.address.split('.');
          if (ipParts.length === 4) {
            return `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0/24`;
          }
        }
      }
    }
    return '192.168.1.0/24';
  }

  private scanNetwork(subnet: string): Promise<DeviceInfo[]> {
    return new Promise((resolve, reject) => {
      try {
        nmap.nmapLocation = 'nmap';
        const quickscan = new nmap.QuickScan(subnet);

        quickscan.on('complete', (data: any[]) => {
          const devices: DeviceInfo[] = data
            .filter((entry) => entry && (entry.ip || entry.address))
            .map((entry) => ({
              ip: entry.ip || entry.address,
              mac: entry.mac || null,
              hostname: entry.hostname || null,
              source: 'nmap',
              details: entry,
            }));
          resolve(devices);
        });

        quickscan.on('error', (error: any) => {
          console.error('Nmap scan error:', error);
          reject(error);
        });

        quickscan.startScan();
      } catch (error) {
        console.error('Error starting nmap scan:', error);
        reject(error);
      }
    });
  }

  private mergeDevices(arpDevices: DeviceInfo[], nmapDevices: DeviceInfo[]): DeviceInfo[] {
    const merged: Record<string, DeviceInfo> = {};

    const add = (device: DeviceInfo) => {
      const key = device.mac || device.ip;
      if (!key) return;
      if (!merged[key]) {
        merged[key] = { ...device };
      } else {
        const existing = merged[key];
        merged[key] = {
          ip: existing.ip || device.ip,
          mac: existing.mac || device.mac,
          hostname: existing.hostname || device.hostname,
          source: 'merged',
          details: { ...(existing.details || {}), ...(device.details || {}) },
        };
      }
    };

    arpDevices.forEach(add);
    nmapDevices.forEach(add);
    return Object.values(merged);
  }

  private getSystemInfo() {
    const interfaces = os.networkInterfaces();
    const networkInterfaces = [] as Array<{
      name: string;
      address: string;
      family: string;
      mac: string;
      internal: boolean;
      cidr: string | null;
    }>;

    for (const [name, ifaceList] of Object.entries(interfaces)) {
      if (!ifaceList) continue;
      for (const addr of ifaceList) {
        networkInterfaces.push({
          name,
          address: addr.address,
          family: addr.family,
          mac: addr.mac,
          internal: addr.internal,
          cidr: addr.cidr || null,
        });
      }
    }

    const userInfo = os.userInfo();

    return {
      hardware: {
        architecture: os.arch(),
        cpuModel: os.cpus()[0]?.model || null,
        cpuCores: os.cpus().length,
        totalMemory: os.totalmem(),
        freeMemory: os.freemem(),
      },
      network: {
        interfaces: networkInterfaces,
      },
      environment: {
        env: process.env,
        cwd: process.cwd(),
        execPath: process.execPath,
      },
      userInfo: {
        username: userInfo.username,
        homedir: userInfo.homedir,
      },
      uptime: {
        systemUptime: os.uptime(),
        processUptime: process.uptime(),
      },
    };
  }

  async getHello() {
    const subnet = this.getLocalSubnet();
    const [arpDevices, nmapDevices] = await Promise.all([
      this.getArpTable(),
      this.scanNetwork(subnet).catch((error) => {
        console.warn('Nmap scan failed, continuing with ARP only.', error);
        return [] as DeviceInfo[];
      }),
    ]);

    const mergedDevices = this.mergeDevices(arpDevices, nmapDevices);
    const newDevices: string[] = [];

    mergedDevices.forEach((device) => {
      if (device.mac && !this.knownDevices.includes(device.mac)) {
        this.knownDevices.push(device.mac);
        newDevices.push(device.mac);
      }
    });

    return {
      summary: {
        totalArp: arpDevices.length,
        totalNmap: nmapDevices.length,
        totalMerged: mergedDevices.length,
        totalKnownDevices: this.knownDevices.length,
        totalNewDevices: newDevices.length,
      },
      devices: {
        // subnet,
        // sources: {
        //   arp: arpDevices,
        //   nmap: nmapDevices,
        // },
        newDevices,
        totalDevices: mergedDevices,
        // knownDevices: this.knownDevices,
      },
      // systemInfo: this.getSystemInfo(),
    };
  }
}
