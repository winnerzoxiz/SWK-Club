// -------------------- Imports & Config --------------------
const express = require('express');
const path = require('path');
const session = require('express-session');
const dbconnection = require('./database');
const multer = require('multer');
const fs = require('fs');
const csv = require('csv-parser');
const ExcelJS = require('exceljs');
const bcrypt = require('bcrypt');
const checkSystem = require("./checkSystem");
 
const app = express();
const PORT = process.env.PORT || 90;
const SESSION_SECRET = process.env.SESSION_SECRET || 'your-secret-key-change-in-production';
const upload = multer({ dest: 'uploads/' });


// -------------------- Middleware --------------------
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000
  }
}));
app.use(checkSystem);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


// -------------------- Utilities --------------------
// Auth middleware
function isUser(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/');
}
function isAdmin(req, res, next) {
  if (req.session.admin) return next();
  res.status(403).send('คุณไม่มีสิทธิ์เข้าถึงหน้านี้');
}

// Database query helper
const dbQuery = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    dbconnection.query(sql, params, (err, results) => {
      if (err) {
        console.error('Database error:', err);
        reject(err);
      } else {
        resolve(results);
      }
    });
  });
};


// -------------------- Authentication Functions --------------------
const authenticateAdmin = async (email, password) => {
  const sql = 'SELECT * FROM admins WHERE email = ?';
  const results = await dbQuery(sql, [email]);
  if (results.length === 0) return { success: false };
  const admin = results[0];
  const isPasswordValid = password.trim() === admin.password.trim();
  if (!isPasswordValid) return { success: false };
  return { success: true, user: admin };
};

const authenticateUser = async (email, password) => {
  try {
    const sql = 'SELECT * FROM users WHERE email = ?';
    const results = await dbQuery(sql, [email]);
    if (results.length === 0) {
      return { success: false, message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' };
    }
    const user = results[0];
    const isPasswordValid = password === user.password;
    if (!isPasswordValid) {
      return { success: false, message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' };
    }
    return { success: true, user };
  } catch (error) {
    console.error('Authentication error:', error);
    return { success: false, message: 'เกิดข้อผิดพลาดในระบบ' };
  }
};


// -------------------- Club & User Utilities --------------------
const getUserRegistrations = async (email) => {
  try {
    const sql = `
      SELECT club.name AS name, club.Room AS Room, club.name_teachers AS name_teachers
      FROM registrations_club
      JOIN club ON registrations_club.club_name = club.name
      WHERE registrations_club.email = ?
    `;
    const results = await dbQuery(sql, [email]);
    return results;
  } catch (error) {
    console.error('Error fetching user registrations with room:', error);
    throw error;
  }
};

const getClubsWithCount = async (category = null) => {
  try {
    let sql = `
      SELECT club.*, (
        SELECT COUNT(*) FROM registrations_club WHERE registrations_club.club_name = club.name
      ) AS currentCount
      FROM club
    `;
    const params = [];
    if (category) {
      sql += ' WHERE category = ?';
      params.push(category);
    }
    return await dbQuery(sql, params);
  } catch (error) {
    console.error('Error fetching clubs:', error);
    throw error;
  }
};

const checkClubRegistration = async (email, clubName) => {
  try {
    const sql = 'SELECT * FROM registrations_club WHERE email = ? AND club_name = ?';
    const results = await dbQuery(sql, [email, clubName]);
    return results.length > 0;
  } catch (error) {
    console.error('Error checking club registration:', error);
    throw error;
  }
};

const getClubCapacity = async (clubName) => {
  try {
    const countSql = 'SELECT COUNT(*) AS count FROM registrations_club WHERE club_name = ?';
    const maxSql = 'SELECT maximum_users FROM club WHERE name = ?';
    const [countResults, maxResults] = await Promise.all([
      dbQuery(countSql, [clubName]),
      dbQuery(maxSql, [clubName])
    ]);
    if (maxResults.length === 0) throw new Error('Club not found');
    return {
      current: countResults[0].count,
      maximum: maxResults[0].maximum_users
    };
  } catch (error) {
    console.error('Error getting club capacity:', error);
    throw error;
  }
};

const registerUserToClub = async (email, clubName) => {
  try {
    const userSql = 'SELECT name_users, classroom, number FROM users WHERE email = ?';
    const userResults = await dbQuery(userSql, [email]);
    if (userResults.length === 0) throw new Error('User not found');
    const { name_users, classroom, number } = userResults[0];
    const clubSql = 'SELECT name_teachers, conditions FROM club WHERE name = ?';
    const clubResults = await dbQuery(clubSql, [clubName]);
    if (clubResults.length === 0) throw new Error('Club not found');
    const { name_teachers, conditions } = clubResults[0];

    const insertSql = `
  INSERT INTO registrations_club
    (name_users, email, classroom, number, club_name, name_teachers, conditions)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`;

    await dbQuery(insertSql, [
      name_users,
      email,
      classroom,
      number,
      clubName,
      name_teachers,
      conditions
    ]);


    return { success: true };
  } catch (error) {
    console.error('Error registering user to club:', error);
    return { success: false, error };
  }
};


// -------------------- Routes: Auth & User --------------------
app.get('/', (req, res) => {
  const message = req.session.message;
  req.session.message = null;
  res.render('index', { title: 'เข้าสู่ระบบ', message });
});

app.post('/', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      req.session.message = 'กรุณากรอกอีเมลและรหัสผ่าน';
      return res.redirect('/');
    }
    // ตรวจสอบ Admin ก่อน
    let authResult = await authenticateAdmin(email, password);
    if (authResult.success) {
      req.session.admin = authResult.user;
      return res.redirect('/admin');
    }
    // ถ้าไม่ใช่ admin ตรวจสอบ user
    authResult = await authenticateUser(email, password);
    if (authResult.success) {
      req.session.user = authResult.user;
      return res.redirect('/user');
    }
    req.session.message = authResult.message || 'อีเมลหรือรหัสผ่านไม่ถูกต้อง';
    res.redirect('/');
  } catch (error) {
    console.error('Login error:', error);
    req.session.message = 'เกิดข้อผิดพลาดในระบบ';
    res.redirect('/');
  }
});

app.post('/logout', (req, res) => {
  req.session.admin = null;
  req.session.user = null;
  req.session.destroy(err => {
    if (err) return res.status(500).send('เกิดข้อผิดพลาด');
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});

app.get('/user', isUser, async (req, res) => {
  try {
    const selectedCategory = req.query.category;
    const search = req.query.search; // ✅ รับค่าค้นหาจาก query
    const user = req.session.user;

    let message = '';
    const clubName = decodeURIComponent(req.query.club || '');
    if (req.query.success) {
      message = `ลงทะเบียนชุมนุม "${clubName}" สำเร็จ!`;
    } else if (req.query.duplicate) {
      message = `ซ้ำ: คุณไม่สามารถลงทะเบียนชุมนุมเดิมได้`;
    } else if (req.query.error) {
      message = `ผิดพลาด: คุณได้ลงทะเบียนชุมนุมอื่นไปแล้ว`;
    } else if (req.query.full) {
      message = `เต็ม: ชุมนุม "${clubName}" เต็มแล้ว`;
    }

    let sql = `
      SELECT club.*, (
        SELECT COUNT(*) 
        FROM registrations_club 
        WHERE registrations_club.club_name = club.name
      ) AS currentCount
      FROM club
      WHERE 1=1
    `;
    const params = [];

    if (selectedCategory) {
      sql += ' AND category = ?';
      params.push(selectedCategory);
    }

    if (search) {
      sql += ' AND club.name LIKE ?';
      params.push(`%${search}%`);
    }

    const clubs = await dbQuery(sql, params);

    const regSql = `
      SELECT c.name, c.Room, c.name_teachers
      FROM registrations_club rc
      JOIN club c ON rc.club_name = c.name
      WHERE rc.email = ?
    `;
    const registeredClubs = await dbQuery(regSql, [user.email]);

    res.render('user', {
      title: 'ผู้ใช้',
      clubs,
      selectedCategory,
      search,
      user,
      message,
      registeredClubs,
      contentToggleDefault: true
    });
  } catch (err) {
    console.error('เกิดข้อผิดพลาดในการโหลดข้อมูลผู้ใช้:', err);
    res.status(500).send('เกิดข้อผิดพลาดในระบบ');
  }
});


app.post('/register-club', isUser, async (req, res) => {
  const email = req.session.user.email;
  const { club_name } = req.body;
  try {
    const alreadyRegistered = await checkClubRegistration(email, club_name);
    if (alreadyRegistered) {
      return res.redirect(`/user?duplicate=1&club=${encodeURIComponent(club_name)}`);
    }
    const { current, maximum } = await getClubCapacity(club_name);
    if (current >= maximum) {
      return res.redirect(`/user?full=1&club=${encodeURIComponent(club_name)}`);
    }
    const result = await registerUserToClub(email, club_name);
    if (!result.success) {
      return res.redirect('/user?error=1');
    }
    return res.redirect(`/user?success=1&club=${encodeURIComponent(club_name)}`);
  } catch (error) {
    console.error('Registration error:', error);
    return res.redirect('/user?error=1');
  }
});


// -------------------- Routes: Admin Club --------------------
app.get('/admin', isAdmin, async (req, res) => {
  try {
    // ดึงข้อมูลผู้ลงทะเบียน
    const [rows] = await dbconnection.promise().query(`
      SELECT
        (SELECT COUNT(DISTINCT u.id)
         FROM users u
         JOIN registrations_club r ON u.email = r.email) AS registered,
        (SELECT COUNT(*) FROM users) -
        (SELECT COUNT(DISTINCT u.id)
         FROM users u
         JOIN registrations_club r ON u.email = r.email) AS not_registered
    `);
    // ดึงสถานะระบบ
    const [configRows] = await dbconnection.promise().query(`
      SELECT system_status FROM system_config LIMIT 1
    `);
    const systemStatus = configRows[0].system_status;
    res.render('admin', {
      registered: rows[0].registered,
      notRegistered: rows[0].not_registered,
      systemStatus
    });
  } catch (err) {
    console.error('DB error:', err);
    res.status(500).send('เกิดข้อผิดพลาดจากเซิร์ฟเวอร์');
  }
});

app.get('/admin_club', isAdmin, async (req, res) => {
  try {
    const search = req.query.search || ''; // รับค่าค้นหาจาก query

    let sql = `
      SELECT name, category, name_teachers, maximum_users, Room, conditions
      FROM club
      WHERE 1=1
    `;
    const params = [];

    if (search.trim() !== '') {
      sql += ' AND name LIKE ? ';
      params.push(`%${search}%`);
    }

    sql += ' ORDER BY name ASC';

    const clubs = await dbQuery(sql, params);

    res.render('admin_club', {
      admin: req.session.admin,
      clubs,
      search
    });
  } catch (error) {
    console.error('Error fetching clubs for admin_club:', error);
    res.status(500).send('เกิดข้อผิดพลาดในการโหลดข้อมูลชุมนุม');
  }
});


app.get('/add_allclub', isAdmin, (req, res) => {
  res.render('add_allclub', { message: '' });
});

app.get('/add_club', isAdmin, (req, res) => {
  res.render('add_club', { message: '' });
});

app.post('/add_club', isAdmin, (req, res) => {
  const { name, name_teachers, category, maximum_users, Room, conditions } = req.body;
  if (!name || !name_teachers || !category || !maximum_users || !Room || !conditions) {
    return res.render('add_club', {
      title: 'เพิ่มชุมนุม',
      message: 'กรุณากรอกข้อมูลให้ครบถ้วน'
    });
  }
  const sql = 'INSERT INTO club (name, name_teachers, category, maximum_users, Room, conditions) VALUES (?, ?, ?, ?, ?, ?)';
  dbconnection.query(sql, [name, name_teachers, category, maximum_users, Room, conditions], (err, result) => {
    if (err) {
      console.error('Error adding club:', err);
      return res.render('add_club', {
        title: 'เพิ่มชุมนุม',
        message: 'เกิดข้อผิดพลาดในการเพิ่มชุมนุม'
      });
    }
    res.redirect('/admin_club');
  });
});
app.post('/admin/toggle-system', isAdmin, async (req, res) => {
  try {
    const newStatus = req.body.system_status === 'open' ? 'open' : 'closed';
    await dbconnection.promise().query(
      "UPDATE system_config SET system_status = ? WHERE id = 1",
      [newStatus]
    );
    res.redirect('/admin');
  } catch (err) {
    console.error('DB error:', err);
    res.status(500).send('เกิดข้อผิดพลาดจากเซิร์ฟเวอร์');
  }
});


// -------------------- Routes: Admin Students --------------------
app.get('/admin_students', isAdmin, async (req, res) => {
  try {
    const search = req.query.search || ''; // รับค่าค้นหาจาก query
    let sql = `
      SELECT name_users, email, password, classroom, number 
      FROM users 
      WHERE 1=1
    `;
    const params = [];

    // ถ้ามีการค้นหา
    if (search.trim() !== '') {
      sql += ' AND (name_users LIKE ? OR email LIKE ?) ';
      params.push(`%${search}%`, `%${search}%`);
    }


    // จัดเรียงผลลัพธ์
    sql += ' ORDER BY classroom ASC, number ASC, name_users ASC';

    const users = await dbQuery(sql, params);

    res.render('admin_students', {
      admin: req.session.admin,
      users,
      search
    });
  } catch (error) {
    console.error('Error fetching users for admin_students:', error);
    res.status(500).send('เกิดข้อผิดพลาดในการโหลดข้อมูลนักเรียน');
  }
});

app.get('/add_allstudents', isAdmin, (req, res) => {
  res.render('add_allstudents', { message: '' });
});
app.get('/add_students', isAdmin, (req, res) => {
  res.render('add_students', { message: '' });
});
app.post('/add_students', isAdmin, async (req, res) => {
  const { name_users, email, password, classroom, number } = req.body;
  if (!name_users || !email || !password || !classroom || !number) {
    return res.render('add_students', {
      title: 'เพิ่มนักเรียน',
      message: 'กรุณากรอกข้อมูลให้ครบถ้วน'
    });
  }
  try {
    const sql = 'INSERT INTO users (name_users, email, password, classroom, number) VALUES (?, ?, ?, ?, ?)';
    dbconnection.query(sql, [name_users, email, password, classroom, number], (err, result) => {
      if (err) {
        console.error('Error adding student:', err);
        return res.render('add_students', {
          title: 'เพิ่มนักเรียน',
          message: 'เกิดข้อผิดพลาดในการเพิ่มนักเรียน'
        });
      }
      res.redirect('/admin_students');
    });
  } catch (err) {
    console.error('Hashing error:', err);
    res.render('add_students', {
      title: 'เพิ่มนักเรียน',
      message: 'เกิดข้อผิดพลาดในการเข้ารหัสรหัสผ่าน'
    });
  }
});


// -------------------- Routes: Admin Register --------------------
app.get('/admin_register', isAdmin, async (req, res) => {
  try {
    const search = req.query.search || ''; // รับค่าค้นหา
    let sql = `
      SELECT name_users, email, classroom, number, club_name, name_teachers, conditions
      FROM registrations_club
      WHERE 1=1
    `;
    const params = [];

    // ถ้ามีการค้นหา
    if (search.trim() !== '') {
      sql += ` AND (
        name_users LIKE ? OR 
        email LIKE ? OR  
        club_name LIKE ?
      )`;
      const searchParam = `%${search}%`;
      params.push(searchParam, searchParam, searchParam);
    }

    sql += ' ORDER BY classroom ASC, number ASC';

    const registrations = await dbQuery(sql, params);

    res.render('admin_register', {
      admin: req.session.admin,
      registrations,
      search
    });
  } catch (error) {
    console.error('Error fetching registrations for admin_register:', error);
    res.status(500).send('เกิดข้อผิดพลาดในการโหลดข้อมูลนักเรียน');
  }
});


app.get('/add_register', isAdmin, (req, res) => {
  res.render('add_register', { message: '' });
});
app.post('/add_register', isAdmin, async (req, res) => {
  const { name_users, email, name_teachers, classroom, number, club_name } = req.body;
  if (!name_users || !email || !name_teachers || !classroom || !number || !club_name || !club_name ) {
    return res.render('add_register', {
      title: 'เพิ่มนักเรียนเข้าชุมนุม',
      message: 'กรุณากรอกข้อมูลให้ครบถ้วน'
    });
  }
  try {
    const sql = 'INSERT INTO registrations_club (name_users, email, name_teachers, classroom, number, club_name) VALUES (?, ?, ?, ?, ?, ?)';
    dbconnection.query(sql, [name_users, email, name_teachers, classroom, number, club_name], (err, result) => {
      if (err) {
        console.error('Error adding student:', err);
        return res.render('add_register', {
          title: 'เพิ่มนักเรียน',
          message: 'เกิดข้อผิดพลาดในการเพิ่มนักเรียน'
        });
      }
      res.redirect('/admin_register');
    });
  } catch (err) {
    console.error('Hashing error:', err);
    res.render('add_register', {
      title: 'เพิ่มนักเรียน',
      message: 'เกิดข้อผิดพลาดในการเข้ารหัสรหัสผ่าน'
    });
  }
});


// -------------------- Routes: Admin Unregistered --------------------
app.get('/admin_unregister', isAdmin, async (req, res) => {
  try {
    const unregisteredByRoom = await dbQuery(`
      SELECT 
        u.classroom AS classroom,
        COUNT(*) AS unregistered_count
      FROM users u
      LEFT JOIN registrations_club r
        ON u.email = r.email AND r.club_name IS NOT NULL
      WHERE r.email IS NULL
      GROUP BY u.classroom
      ORDER BY u.classroom
    `);
    res.render('admin_unregister', {
      admin: req.session.admin,
      unregisteredByRoom
    });
  } catch (error) {
    console.error('Error fetching unregistered users:', error);
    res.status(500).send('เกิดข้อผิดพลาดในการโหลดข้อมูล');
  }
});


// -------------------- Routes: Admin Unregistered Detail --------------------
app.get('/admin_unregisterdetail/:classroom', isAdmin, async (req, res) => {
  const { classroom } = req.params;
  try {
    const users = await dbQuery(`
      SELECT u.name_users, u.classroom, u.number, u.email, u.password
      FROM users u
      LEFT JOIN registrations_club r 
        ON u.email = r.email AND r.club_name IS NOT NULL
      WHERE r.email IS NULL AND u.classroom = ?
      ORDER BY u.number
    `, [classroom]);
    res.render('admin_unregisterdetail', {
      admin: req.session.admin,
      classroom,
      users
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading data');
  }
});


// -------------------- Routes: Admin Club Members --------------------
app.get('/admin_clubmembers/:clubName', isAdmin, async (req, res) => {
  const { clubName } = req.params;
  try {
    const members = await dbQuery(`
      SELECT r.name_users, r.classroom, r.number, r.email, c.category, c.name_teachers
      FROM registrations_club r
      JOIN club c ON TRIM(r.club_name) = TRIM(c.name)
      WHERE TRIM(r.club_name) = TRIM(?)
      ORDER BY r.classroom ASC, r.number ASC, r.name_users ASC
    `, [clubName]);
    res.render('admin_clubmembers', {
      admin: req.session.admin,
      clubName,
      members
    });
  } catch (err) {
    console.error('Error fetching club members:', err);
    res.status(500).send('เกิดข้อผิดพลาดในการโหลดข้อมูลสมาชิก');
  }
});


// -------------------- Routes: Admin Club Capacity --------------------
app.get('/admin_club_capacity', isAdmin, async (req, res) => {
  try {
    const selectedCategory = req.query.category;

    let sql = `
      SELECT 
        c.name AS club_name,
        c.category,
        c.maximum_users,
        IFNULL(rc.registered_count, 0) AS registered_count,
        (c.maximum_users - IFNULL(rc.registered_count, 0)) AS remaining_slots
      FROM club c
      LEFT JOIN (
        SELECT club_name, COUNT(*) AS registered_count
        FROM registrations_club
        GROUP BY club_name
      ) rc ON c.name = rc.club_name
    `;

    const params = [];
    if (selectedCategory) {
      sql += ` WHERE c.category = ? `;
      params.push(selectedCategory);
    }

    sql += `
      ORDER BY 
        c.category COLLATE utf8mb4_unicode_ci ASC,
        c.name COLLATE utf8mb4_unicode_ci ASC
    `;

    const clubs = await dbQuery(sql, params);

    res.render('admin_club_capacity', {
      admin: req.session.admin,
      clubs,
      selectedCategory
    });
  } catch (error) {
    console.error('Error fetching club capacity:', error);
    res.status(500).send('เกิดข้อผิดพลาดในการโหลดข้อมูล');
  }
});

// -------------------- API --------------------
// 1) ค้นหานักเรียนจาก email
app.get('/api/user/:email', (req, res) => {
  const email = req.params.email;

  dbconnection.query(
    'SELECT name_users, classroom, number FROM users WHERE email = ?',
    [email],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (results.length === 0) return res.json({});
      res.json(results[0]);
    }
  );
});

// 2) ดึง category ทั้งหมดจาก club
app.get('/api/categories', (req, res) => {
  dbconnection.query(
    'SELECT DISTINCT category FROM club',
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json(results);
    }
  );
});

// 3) ดึง club ตาม category 
app.get('/api/clubs/:category', (req, res) => {
  const category = req.params.category;

  dbconnection.query(
    'SELECT name, name_teachers, conditions FROM club WHERE category = ?',
    [category],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'DB error' });
      }
      res.json(results);
    }
  );
});



// -------------------- Routes: CSV Import --------------------
// Import clubs from CSV
app.post('/admin_club/import', isAdmin, upload.single('csvfile'), async (req, res) => {
  // ตรวจสอบว่ามีไฟล์ CSV ถูกอัพโหลดหรือไม่
  if (!req.file) {
    return res.render('add_allclub', { message: 'กรุณาเลือกไฟล์ CSV ก่อนอัพโหลด' });
  }

  const clubs = [];    // เก็บข้อมูลชุมนุมที่อ่านได้จากไฟล์
  const errors = [];   // เก็บข้อความ error จากการอ่านไฟล์

  try {
    // อ่านข้อมูลจากไฟล์ CSV
    await new Promise((resolve, reject) => {
      fs.createReadStream(req.file.path)
        .pipe(csv({ skipEmptyLines: true, trim: true, encoding: 'utf8' }))
        .on('data', (row) => {
          // ทำความสะอาด key ของแต่ละ column
          const cleanedRow = {};
          Object.keys(row).forEach(key => { cleanedRow[key.trim()] = row[key]; });

          // สร้าง object ข้อมูลชุมนุม
          const clubData = {
            name: cleanedRow['ชื่อชุมนุม']?.trim() || null,
            name_teachers: cleanedRow['ครูที่ปรึกษา']?.trim() || null,
            category: cleanedRow['กลุ่มสาระการเรียนรู้']?.trim() || null,
            maximum_users: parseInt(cleanedRow['จำนวนนักเรียน'], 10) || 0,
            Room: cleanedRow['ห้อง']?.trim() || null,
            conditions: cleanedRow['เงื่อนไขการรับ']?.trim() || null
          };

          // ตรวจสอบข้อมูลที่จำเป็น
          if (!clubData.name) {
            errors.push(`แถวที่ ${clubs.length + 1}: ไม่พบชื่อวิชาเรียน`);
            return;
          }
          if (!clubData.name_teachers) {
            errors.push(`แถวที่ ${clubs.length + 1}: ไม่พบชื่อครูที่ปรึกษา`);
            return;
          }

          clubs.push(clubData);
        })
        .on('end', () => {
          // ลบไฟล์ CSV ชั่วคราวหลังอ่านเสร็จ
          fs.unlink(req.file.path, (err) => { if (err) console.error(err); });
          resolve();
        })
        .on('error', (err) => reject(err));
    });

    // กรณีไม่มีข้อมูลที่ถูกต้อง
    if (clubs.length === 0) {
      const errorMessage = errors.length > 0
        ? `ไม่พบข้อมูลที่ถูกต้อง: ${errors.join(', ')}`
        : 'ไม่พบข้อมูลชุมนุมในไฟล์ CSV หรือข้อมูลไม่ถูกต้อง';
      return res.render('add_allclub', { message: errorMessage });
    }

    // -------------------- Insert Clubs to Database --------------------
    let successCount = 0;
    const insertErrors = [];

    for (let i = 0; i < clubs.length; i++) {
      const club = clubs[i];
      try {
        await dbQuery(
          'INSERT INTO club (name, name_teachers, category, maximum_users, Room, conditions) VALUES (?, ?, ?, ?, ?, ?)',
          [club.name, club.name_teachers, club.category, club.maximum_users, club.Room, club.conditions]
        );
        successCount++;
      } catch (err) {
        insertErrors.push(`แถวที่ ${i + 1} (${club.name}): ${err.message}`);
      }
    }

    // -------------------- สร้างข้อความแจ้งผลลัพธ์ --------------------
    let message = `นำเข้าข้อมูลสำเร็จ ${successCount} รายการจากทั้งหมด ${clubs.length} รายการ`;
    if (insertErrors.length > 0) message += `\nข้อผิดพลาด: ${insertErrors.join(', ')}`;
    if (errors.length > 0) message += `\nข้อมูลที่ไม่ถูกต้อง: ${errors.join(', ')}`;

    // เก็บข้อความแจ้งเตือนใน session เพื่อแสดงผลหลัง redirect
    req.session.importMessage = message;
    req.session.importType = insertErrors.length > 0 ? 'warning' : 'success';
    res.redirect('/admin_club');

  } catch (err) {
    // -------------------- Error Handling --------------------
    console.error('Error importing CSV:', err);
    if (req.file?.path) fs.unlink(req.file.path, () => { });
    req.session.importMessage = `เกิดข้อผิดพลาดในการนำเข้าไฟล์ CSV: ${err.message}`;
    req.session.importType = 'error';
    res.redirect('/admin_club/import');
  }
});

// Import users from CSV
app.post('/admin_user/import', isAdmin, upload.single('csvfile'), async (req, res) => {
  if (!req.file) {
    return res.render('add_allstudents', { message: 'กรุณาเลือกไฟล์ CSV ก่อนอัพโหลด' });
  }

  const users = [];
  const errors = [];

  try {
    // อ่านไฟล์ CSV
    await new Promise((resolve, reject) => {
      fs.createReadStream(req.file.path)
        .pipe(csv({ skipEmptyLines: true, trim: true, encoding: 'utf8' }))
        .on('data', (row) => {
          const cleanedRow = {};
          Object.keys(row).forEach(key => cleanedRow[key.trim()] = row[key]);

          const userData = {
            name_users: cleanedRow['ชื่อผู้ใช้']?.trim() || null,
            email: cleanedRow['อีเมล']?.trim() || null,
            password: cleanedRow['รหัสผ่าน']?.trim() || null,
            classroom: cleanedRow['ห้องเรียน']?.trim() || null,
            number: cleanedRow['เลขที่']?.trim() || null
          };

          const missingFields = [];
          if (!userData.name_users) missingFields.push('ชื่อผู้ใช้');
          if (!userData.email) missingFields.push('อีเมล');
          if (!userData.password) missingFields.push('รหัสผ่าน');
          if (!userData.classroom) missingFields.push('ห้องเรียน');
          if (!userData.number) missingFields.push('เลขที่');

          if (missingFields.length > 0) {
            errors.push(`แถวที่ ${users.length + 1}: ข้อมูลไม่ครบ (${missingFields.join(', ')})`);
            return;
          }

          users.push(userData);
        })
        .on('end', () => {
          fs.unlink(req.file.path, err => {
            if (err) console.error('Error deleting temp CSV file:', err);
          });
          resolve();
        })
        .on('error', (err) => reject(err));
    });

    if (users.length === 0) {
      const msg = errors.length > 0 ? `ไม่พบข้อมูลที่ถูกต้อง: ${errors.join(', ')}` : 'ไม่พบข้อมูลผู้ใช้ในไฟล์ CSV หรือข้อมูลไม่ถูกต้อง';
      return res.render('add_allstudents', { message: msg });
    }

    // Insert users ลง DB
    let successCount = 0;
    const insertErrors = [];

    for (let i = 0; i < users.length; i++) {
      const user = users[i];
      try {
        const sql = 'INSERT INTO users (name_users, email, password, classroom, number) VALUES (?, ?, ?, ?, ?)';
        await dbQuery(sql, [user.name_users, user.email, user.password, user.classroom, user.number]);
        successCount++;
      } catch (err) {
        insertErrors.push(`แถวที่ ${i + 1} (${user.name_users}): ${err.message}`);
      }
    }

    let message = `นำเข้าข้อมูลสำเร็จ ${successCount} รายการจากทั้งหมด ${users.length} รายการ`;
    if (insertErrors.length > 0) message += `\nข้อผิดพลาด: ${insertErrors.join(', ')}`;
    if (errors.length > 0) message += `\nข้อมูลที่ไม่ถูกต้อง: ${errors.join(', ')}`;

    req.session.importMessage = message;
    req.session.importType = insertErrors.length > 0 ? 'warning' : 'success';

    return res.redirect('/admin_students');

  } catch (err) {
    console.error('Error importing CSV:', err);
    if (req.file?.path) fs.unlink(req.file.path, () => { });
    req.session.importMessage = `เกิดข้อผิดพลาดในการนำเข้าไฟล์ CSV: ${err.message}`;
    req.session.importType = 'error';
    return res.redirect('/admin_students/import');
  }
});


// -------------------- template Club.csv Download ----------------------

app.get('/admin_club/download-template', isAdmin, (req, res) => {
  const file = __dirname + '/public/csv_templates/Test_club_last.csv';
  res.download(file, 'import_club_template.csv', (err) => {
    if (err) {
      console.error('Error downloading template:', err);
      res.status(500).send('เกิดข้อผิดพลาดในการดาวน์โหลดไฟล์');
    }
  });
});

// -------------------- template Users.csv Download ----------------------

app.get('/admin_user/download-template', isAdmin, (req, res) => {
  const file = __dirname + '/public/csv_templates/Test_user_last.csv';
  res.download(file, 'import_user_template.csv', (err) => {
    if (err) {
      console.error('Error downloading template:', err);
      res.status(500).send('เกิดข้อผิดพลาดในการดาวน์โหลดไฟล์');
    }
  });
});


// -------------------- Routes: Export to Excel --------------------
app.get('/admin_register/export', isAdmin, async (req, res) => {
  try {
    const registrations = await dbQuery(`
      SELECT email, name_users, classroom, number, club_name
      FROM registrations_club
      ORDER BY id DESC
    `);

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Registrations');

    worksheet.columns = [
      { header: 'รหัสประจำตัวนักเรียน', key: 'email', width: 25 },
      { header: 'ชื่อผู้ใช้', key: 'name_users', width: 25 },
      { header: 'ห้องเรียน', key: 'classroom', width: 15 },
      { header: 'เลขที่', key: 'number', width: 10 },
      { header: 'ชื่อชุมนุม', key: 'club_name', width: 25 },
    ];

    registrations.forEach(reg => worksheet.addRow(reg));

    const buffer = await workbook.xlsx.writeBuffer();
    res.setHeader('Content-Disposition', 'attachment; filename="registrations.xlsx"');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buffer);

  } catch (err) {
    console.error('Error exporting registrations:', err);
    req.session.importMessage = `เกิดข้อผิดพลาดในการ export ข้อมูล: ${err.message}`;
    req.session.importType = 'error';
    res.redirect('/admin_register');
  }
});

app.get('/admin_unregisterdetail/export/:classroom', isAdmin, async (req, res) => {
  const { classroom } = req.params;

  try {
    const users = await dbQuery(`
      SELECT u.name_users, u.classroom, u.number, u.email, u.password
      FROM users u
      LEFT JOIN registrations_club r 
        ON u.email = r.email AND r.club_name IS NOT NULL
      WHERE r.email IS NULL AND u.classroom = ?
      ORDER BY u.number
    `, [classroom]);

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('Unregistered Users');

    worksheet.columns = [
      { header: 'ชื่อนักเรียน', key: 'name_users', width: 25 },
      { header: 'ชั้น', key: 'classroom', width: 15 },
      { header: 'เลขที่', key: 'number', width: 10 },
      { header: 'อีเมลล์', key: 'email', width: 25 },
      { header: 'รหัสผ่าน', key: 'password', width: 20 },
    ];

    users.forEach(u => worksheet.addRow(u));

    const buffer = await workbook.xlsx.writeBuffer();
    res.setHeader('Content-Disposition', `attachment; filename="unregistered_${classroom}.xlsx"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buffer);

  } catch (err) {
    console.error('Error exporting unregistered users:', err);
    res.status(500).send('เกิดข้อผิดพลาดในการ export Excel');
  }
});

app.get('/admin_clubmembers/export/:classroom', isAdmin, async (req, res) => {
  const { classroom } = req.params;

  try {
    const registrations_club = await dbQuery(`
      SELECT name_users, classroom, number, email, club_name, name_teachers
      FROM registrations_club 
    `, [classroom]);

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet('clubmember Users');

    worksheet.columns = [
      { header: 'ชื่อนักเรียน', key: 'name_users', width: 25 },
      { header: 'ชั้น', key: 'classroom', width: 15 },
      { header: 'เลขที่', key: 'number', width: 10 },
      { header: 'อีเมลล์', key: 'email', width: 25 },
      { header: 'ชื่อชุมนุม', key: 'club_name', width: 20 },
      { header: 'ชื่อครูผู้สอน', key: 'name_teachers', width: 20 },
    ];

    registrations_club.forEach(u => worksheet.addRow(u));

    const buffer = await workbook.xlsx.writeBuffer();
    res.setHeader('Content-Disposition', `attachment; filename="unregistered_${classroom}.xlsx"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buffer);

  } catch (err) {
    console.error('Error exporting unregistered users:', err);
    res.status(500).send('เกิดข้อผิดพลาดในการ export Excel');
  }
});


// -------------------- Routes: Club Actions --------------------
app.post('/admin_club/delete-club', isAdmin, async (req, res) => {
  const { club_name } = req.body;
  if (!club_name) return res.status(400).json({ success: false, message: 'ไม่มีชื่อชุมนุมที่ต้องการลบ' });

  try {
    await dbQuery('DELETE FROM club WHERE name = ?', [club_name]);
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting club:', err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการลบชุมนุม' });
  }
});

app.post('/admin_club/delete-all-clubs', isAdmin, async (req, res) => {
  try {
    await dbQuery('DELETE FROM club');
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting all clubs:', err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการลบชุมนุมทั้งหมด' });
  }
});

app.get('/admin_club/edit-club/:name', isAdmin, async (req, res) => {
  try {
    const clubName = req.params.name;
    const clubs = await dbQuery('SELECT * FROM club WHERE name = ?', [clubName]);

    if (!clubs.length) return res.status(404).send('ไม่พบข้อมูลชุมนุม');

    res.render('edit_club', {
      title: 'แก้ไขชุมนุม',
      club: clubs[0],
      message: ''
    });
  } catch (err) {
    console.error('Error fetching club for edit:', err);
    res.status(500).send('เกิดข้อผิดพลาดในการโหลดข้อมูลชุมนุม');
  }
});

app.post('/admin_club/edit-club/:name', isAdmin, async (req, res) => {
  const { name, name_teachers, category, maximum_users, Room, conditions } = req.body;
  const oldName = req.params.name;

  if (!name || !name_teachers || !category || !maximum_users || !Room || !conditions) {
    return res.render('edit_club', {
      title: 'แก้ไขชุมนุม',
      club: { name, name_teachers, category, maximum_users, Room, conditions },
      message: 'กรุณากรอกข้อมูลให้ครบถ้วน'
    });
  }

  try {
    await dbQuery(
      'UPDATE club SET name = ?, name_teachers = ?, category = ?, maximum_users = ?, Room = ?, conditions = ? WHERE name = ?',
      [name, name_teachers, category, maximum_users, Room, conditions, oldName]
    );

    res.redirect('/admin_club');
  } catch (err) {
    console.error('Error updating club:', err);
    res.render('edit_club', {
      title: 'แก้ไขชุมนุม',
      club: { name, name_teachers, category, maximum_users, Room, conditions },
      message: 'เกิดข้อผิดพลาดในการแก้ไขชุมนุม'
    });
  }
});


// -------------------- Routes: Student Actions --------------------
app.post('/admin_students/delete-user', isAdmin, async (req, res) => {
  const { name_users } = req.body;
  if (!name_users) return res.status(400).json({ success: false, message: 'ไม่มีชื่อผู้ใช้ที่ต้องการลบ' });

  try {
    await dbQuery('DELETE FROM users WHERE name_users = ?', [name_users]);
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการลบผู้ใช้' });
  }
});

app.post('/admin_students/delete-all-users', isAdmin, async (req, res) => {
  try {
    await dbQuery('DELETE FROM users');
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting all users:', err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการลบผู้ใช้ทั้งหมด' });
  }
});

app.get('/admin_students/edit-user/:name_users', isAdmin, async (req, res) => {
  try {
    const userName = req.params.name_users;
    const users = await dbQuery('SELECT * FROM users WHERE name_users = ?', [userName]);

    if (!users.length) return res.status(404).send('ไม่พบข้อมูลผู้ใช้');

    res.render('edit_user', {
      title: 'แก้ไขผู้ใช้',
      user: users[0],
      message: ''
    });
  } catch (err) {
    console.error('Error fetching user for edit:', err);
    res.status(500).send('เกิดข้อผิดพลาดในการโหลดข้อมูลผู้ใช้');
  }
});

app.post('/admin_students/edit-user/:name_users', isAdmin, async (req, res) => {
  const { name_users, email, password, classroom, number } = req.body;
  const oldName = req.params.name_users;

  if (!name_users || !email || !password || !classroom || !number) {
    return res.render('edit_user', {
      title: 'แก้ไขผู้ใช้',
      user: { name_users, email, password, classroom, number },
      message: 'กรุณากรอกข้อมูลให้ครบถ้วน'
    });
  }

  try {
    await dbQuery(
      'UPDATE users SET name_users = ?, email = ?, password = ?, classroom = ?, number = ? WHERE name_users = ?',
      [name_users, email, password, classroom, number, oldName]
    );

    res.redirect('/admin_students');
  } catch (err) {
    console.error('Error updating user:', err);
    res.render('edit_user', {
      title: 'แก้ไขผู้ใช้',
      user: { name_users, email, password, classroom, number },
      message: 'เกิดข้อผิดพลาดในการแก้ไขผู้ใช้'
    });
  }
});


// -------------------- Routes: Admin Register Actions --------------------
app.post('/admin_register/delete-user', isAdmin, async (req, res) => {
  const { name_users } = req.body;
  if (!name_users) return res.status(400).json({ success: false, message: 'ไม่มีชื่อผู้ใช้ที่ต้องการลบ' });

  try {
    await dbQuery('DELETE FROM registrations_club WHERE name_users = ?', [name_users]);
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting user from registrations_club:', err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการลบผู้ใช้' });
  }
});

app.post('/admin_register/delete-all-users', isAdmin, async (req, res) => {
  try {
    await dbQuery('DELETE FROM registrations_club');
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting all users from registrations_club:', err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการลบผู้ใช้ทั้งหมด' });
  }
});

app.get('/admin_register/edit-registration/:name', isAdmin, async (req, res) => {
  try {
    const name = req.params.name;
    const registrations = await dbQuery('SELECT * FROM registrations_club WHERE name_users = ?', [name]);

    if (!registrations.length) return res.status(404).send('ไม่พบข้อมูลการลงทะเบียน');

    res.render('edit_register', {
      registration: registrations[0],
      message: ''
    });
  } catch (err) {
    console.error('Error fetching registration for edit:', err);
    res.status(500).send('เกิดข้อผิดพลาดในการโหลดข้อมูลการลงทะเบียน');
  }
});

app.post('/admin_register/edit-registration/:name', isAdmin, async (req, res) => {
  const { name_users, classroom, number, club_name, conditions } = req.body;
  const oldName = req.params.name;

  if (!name_users || !classroom || !number || !club_name || !conditions) {
    return res.render('edit_register', {
      registration: { name_users, classroom, number, club_name, conditions },
      message: 'กรุณากรอกข้อมูลให้ครบถ้วน'
    });
  }

  try {
    await dbQuery(
      'UPDATE registrations_club SET name_users = ?, classroom = ?, number = ?, club_name = ?, conditions = ? WHERE name_users = ?',
      [name_users, classroom, number, club_name, conditions, oldName]
    );

    res.redirect('/admin_register');
  } catch (err) {
    console.error('Error updating registration:', err);
    res.render('edit_register', {
      registration: { name_users, classroom, number, club_name, conditions },
      message: 'เกิดข้อผิดพลาดในการแก้ไขข้อมูลการลงทะเบียน'
    });
  }
});



// -------------------- Error Handling --------------------
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).send('เกิดข้อผิดพลาดในระบบ');
});

app.use((req, res) => {
  res.status(404).send('หน้าที่คุณต้องการไม่พบ');
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});


// -------------------- Server Startup --------------------
app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on http://0.0.0.0:90");
});

