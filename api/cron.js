import { PrismaClient } from '@prisma/client';
import { Resend } from 'resend';
import tls from 'tls';
import whoiser from 'whoiser';

const prisma = new PrismaClient();
const resend = new Resend(process.env.RESEND_API_KEY);

// 1. เช็ค Connection & SSL
function checkSite(domain) {
    return new Promise((resolve) => {
        const options = { host: domain, port: 443, servername: domain };
        const socket = tls.connect(options, () => {
            const cert = socket.getPeerCertificate();
            if (!cert || Object.keys(cert).length === 0) {
                resolve({ alive: true, ssl: null }); // ต่อติดแต่ไม่มี SSL
                socket.end(); return;
            }
            const validTo = new Date(cert.valid_to);
            const days = Math.floor((validTo - new Date()) / (86400000));
            resolve({
                alive: true,
                ssl: { issuer: cert.issuer.O || cert.issuer.CN, validTo, days }
            });
            socket.end();
        });
        socket.on('error', (e) => resolve({ alive: false, error: e.message }));
        socket.setTimeout(5000, () => { socket.destroy(); resolve({ alive: false, error: 'Timeout' }); });
    });
}

// 2. เช็ค Domain WHOIS
async function checkWhois(domain) {
    try {
        const data = await whoiser(domain);
        const firstKey = Object.keys(data)[0];
        const info = data[firstKey];
        const dateStr = info['Registry Expiry Date'] || info['Expiry Date'] || info['expires'];
        
        if (dateStr) {
            const validTo = new Date(dateStr);
            const days = Math.floor((validTo - new Date()) / (86400000));
            return { validTo, days };
        }
        return null;
    } catch { return null; }
}

// 3. ส่งอีเมล
async function sendAlert(to, subject, html) {
    if (!to) return;
    try {
        await resend.emails.send({
            from: 'Monitor <onboarding@resend.dev>',
            to: to, subject: subject, html: html
        });
        console.log(`Sent email to ${to}`);
    } catch (e) { console.error('Email Error:', e); }
}

export default async function handler(req, res) {
    const domains = await prisma.domain.findMany({ include: { user: true } });
    const results = [];

    for (const d of domains) {
        // Run Checks
        const siteStatus = await checkSite(d.domainName);
        const whoisStatus = await checkWhois(d.domainName);

        // Update DB
        const updateData = {
            lastChecked: new Date(),
            isAlive: siteStatus.alive,
            lastError: siteStatus.alive ? null : siteStatus.error,
            
            issuer: siteStatus.ssl?.issuer || d.issuer,
            sslValidTo: siteStatus.ssl?.validTo || d.sslValidTo,
            sslDaysLeft: siteStatus.ssl?.days || d.sslDaysLeft,

            domainValidTo: whoisStatus?.validTo || d.domainValidTo,
            domainDaysLeft: whoisStatus?.days || d.domainDaysLeft
        };

        await prisma.domain.update({ where: { id: d.id }, data: updateData });

        // Alert Logic
        if (d.user?.email) {
            // A. เว็บล่ม
            if (!siteStatus.alive) {
                await sendAlert(d.user.email, `🚨 เว็บล่ม: ${d.domainName}`, `<h1 style="color:red">Website Down</h1><p>Error: ${siteStatus.error}</p>`);
            }
            // B. SSL ใกล้หมด (< 7 วัน)
            else if (siteStatus.ssl?.days <= 7) {
                await sendAlert(d.user.email, `🔒 SSL เตือน: ${d.domainName}`, `<p>SSL เหลือ ${siteStatus.ssl.days} วัน</p>`);
            }
            // C. Domain ใกล้หมด (< 30 วัน)
            if (whoisStatus?.days <= 30) {
                await sendAlert(d.user.email, `🌍 Domain เตือน: ${d.domainName}`, `<p>Domain เหลือ ${whoisStatus.days} วัน</p>`);
            }
        }
        results.push({ domain: d.domainName, ...updateData });
    }
    return res.json({ success: true, processed: results.length });
}