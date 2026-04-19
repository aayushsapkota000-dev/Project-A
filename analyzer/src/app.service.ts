import { Injectable } from '@nestjs/common';
import * as os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
// @ts-ignore
import nmap from 'node-nmap';

@Injectable()
export class AppService {
  private knownDevices: string[] = [];

  private async getArpTable(): Promise<any[]> {
    const execAsync = promisify(exec);
    try {
      const { stdout } = await execAsync('arp -a');
      const lines = stdout.split('\n');
      const devices: any[] = [];
      for (const line of lines) {
        const match = line.match(/\? \(([^)]+)\) at ([0-9a-f:]+) on ([^ ]+)/);
        if (match && match[2] !== '(incomplete)' && match[2] !== 'ff:ff:ff:ff:ff:ff') {
          devices.push({
            ip: match[1],
            mac: match[2].toLowerCase(),
            hostname: null, // ARP doesn't provide hostname
          });
        }
      }
      return devices;
    } catch (error) {
      console.error('Error getting ARP table:', error);
      return [];
    }
  }

  async getHello() {
    return new Promise(async (resolve, reject) => {
      const newDevices: Set<string> = new Set();

      // Get devices from ARP table
      const arpDevices = await this.getArpTable();
      console.log('ARP devices:', arpDevices);

      arpDevices.forEach((device) => {
        if (device.mac && !this.knownDevices.includes(device.mac)) {
          newDevices.add(device.mac);
          this.knownDevices.push(device.mac);
        }
      });

      resolve({
        knownDevices: this.knownDevices,
        newDevices: Array.from(newDevices),
        allDevices: arpDevices, // Include full device info
      });
    });
  }
}