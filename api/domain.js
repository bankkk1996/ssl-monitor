import { PrismaClient } from '@prisma/client';
import { createClient } from '@supabase/supabase-js';

const prisma = new PrismaClient();
const supabaseClient = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);

export default async function handler(req, res) {
    const token = req.headers.authorization?.split(' ')[1];
    const { data: { user: authUser } } = await supabaseClient.auth.getUser(token);
    
    if (!authUser) return res.status(401).json({ error: 'Unauthorized' });

    // Sync User & Role
    const user = await prisma.user.upsert({
        where: { id: authUser.id },
        update: { email: authUser.email },
        create: { id: authUser.id, email: authUser.email }
    });

    const isAdmin = user.role === 'ADMIN';

    // GET
    if (req.method === 'GET') {
        const where = isAdmin ? {} : { userId: user.id };
        const domains = await prisma.domain.findMany({
            where,
            orderBy: { sslDaysLeft: 'asc' },
            include: { user: { select: { email: true } } }
        });
        return res.json({ domains, theme: user.theme, isAdmin });
    }

    // POST
    if (req.method === 'POST') {
        const { domainName, priority } = req.body;
        // บันทึกเบื้องต้นไปก่อน เดี๋ยว Cron มาเก็บงานละเอียด
        await prisma.domain.create({
            data: {
                domainName,
                userId: user.id,
                priority: priority || 'Normal'
            }
        });
        // ทริกเกอร์ Cron แบบ manual (optional) หรือรอรอบ
        return res.json({ success: true });
    }

    // DELETE
    if (req.method === 'DELETE') {
        const { id } = req.query;
        const where = isAdmin ? { id: Number(id) } : { id: Number(id), userId: user.id };
        await prisma.domain.deleteMany({ where }); // deleteMany ปลอดภัยกว่าถ้าหาไม่เจอ
        return res.json({ success: true });
    }
}