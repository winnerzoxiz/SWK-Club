const db = require('./database');

/**
 * Middleware สำหรับตรวจสอบสถานะระบบเปิด/ปิด
 * - ถ้าระบบปิด จะป้องกันผู้ใช้ทั่วไปเข้าถึงหน้า user
 * - Admin และ action ที่เกี่ยวกับ admin/add สามารถเข้าถึงได้เสมอ
 */
async function checkSystem(req, res, next) {
    try {
        // ดึงสถานะระบบจากฐานข้อมูล
        const [rows] = await db.promise().query("SELECT system_status FROM system_config LIMIT 1");
        const status = rows[0].system_status;

        // กำหนด path ที่อนุญาตให้เข้าถึงได้เสมอ (login/logout/admin/add)
        const openPaths = ['/', '/login', '/logout'];

        // อนุญาตหน้า admin และ action ทุกตัว
        if (
            openPaths.includes(req.path) ||
            req.path.startsWith('/admin') ||
            req.path.startsWith('/edit') ||
            req.path.startsWith('/api') ||
            req.path.startsWith('/add')
            
        ) {
            return next();
        }

        // ถ้าระบบปิดและไม่ใช่ admin ให้ redirect ไปหน้าแจ้งปิดระบบ
        if (req.session.role !== 'admin' && status === 'closed') {
            const user = req.session.user || {};

            // ดึงข้อมูลชุมนุมที่ผู้ใช้ลงทะเบียน (ถ้ามี)
            let registeredClubs = [];
            if (user.email) {
                const regSql = `
                    SELECT c.name, c.Room, c.name_teachers
                    FROM registrations_club rc
                    JOIN club c ON rc.club_name = c.name
                    WHERE rc.email = ?
                `;
                registeredClubs = await db.promise().query(regSql, [user.email])
                    .then(([rows]) => rows)
                    .catch(() => []);
            }

            // แสดงหน้า user_deadline พร้อมข้อมูลผู้ใช้และชุมนุมที่ลงทะเบียน
            return res.render("user_deadline.ejs", {
                title: 'ปิดระบบแล้ว',
                user,
                registeredClubs,
                message: "ระบบปิดชั่วคราว",
            });
        }

        // ถ้าระบบเปิดหรือเป็น admin ให้ไป middleware ถัดไป
        next();
    } catch (err) {
        // กรณีเกิด error ในการเชื่อมต่อฐานข้อมูลหรือ query
        console.error(err);
        res.status(500).send("Server Error");
    }
}

module.exports = checkSystem;
