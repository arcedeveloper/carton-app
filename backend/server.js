const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();

app.use(helmet());

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Credentials', 'true');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

app.use((req, res, next) => {
    console.log(`📡 ${req.method} ${req.url} desde ${req.headers.origin || 'desconocido'}`);
    next();
});

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Demasiadas peticiones, intentá más tarde' }
});
app.use('/api/', limiter);

app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

pool.connect((err) => {
    if (err) {
        console.error('❌ Error conectando a PostgreSQL:', err);
    } else {
        console.log('✅ Conectado a PostgreSQL');
    }
});

const verificarToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Token requerido' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Token inválido' });
        req.usuarioId = decoded.id;
        req.usuarioRole = decoded.role;
        next();
    });
};

const verificarAdmin = (req, res, next) => {
    if (req.usuarioRole !== 'admin') {
        return res.status(403).json({ error: 'Acceso denegado' });
    }
    next();
};

async function logAccion(usuarioId, accion, ip, detalles = {}) {
    try {
        await pool.query(
            'INSERT INTO logs_seguridad (usuario_id, accion, ip, detalles) VALUES ($1, $2, $3, $4)',
            [usuarioId, accion, ip, JSON.stringify(detalles)]
        );
    } catch (error) {
        console.error('Error guardando log:', error);
    }
}

app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date(),
        uptime: process.uptime()
    });
});

app.get('/api/crear-admin', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        const existe = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', ['admin']);
        
        if (existe.rows.length === 0) {
            const result = await pool.query(
                'INSERT INTO usuarios (usuario, password, role) VALUES ($1, $2, $3) RETURNING id',
                ['admin', hashedPassword, 'admin']
            );
            await pool.query(
                'INSERT INTO tiempo_uso (usuario_id, horas_restantes) VALUES ($1, $2)',
                [result.rows[0].id, 999999]
            );
            res.json({ message: '✅ Admin creado correctamente' });
        } else {
            res.json({ message: 'ℹ️ El admin ya existe' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al crear admin' });
    }
});

app.post('/api/register', 
    body('usuario').isLength({ min: 3, max: 50 }).trim().escape(),
    body('password').isLength({ min: 6 }),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { usuario, password } = req.body;
            const usuarioExistente = await pool.query(
                'SELECT * FROM usuarios WHERE usuario = $1',
                [usuario]
            );
            
            if (usuarioExistente.rows.length > 0) {
                return res.status(400).json({ error: 'Usuario ya registrado' });
            }
            
            const hashedPassword = await bcrypt.hash(password, 10);
            const result = await pool.query(
                'INSERT INTO usuarios (usuario, password, role) VALUES ($1, $2, $3) RETURNING id',
                [usuario, hashedPassword, 'user']
            );
            
            const usuarioId = result.rows[0].id;
            await pool.query(
                'INSERT INTO tiempo_uso (usuario_id, horas_restantes, ultima_actividad) VALUES ($1, $2, NOW())',
                [usuarioId, 0]
            );
            
            const token = jwt.sign(
                { id: usuarioId, usuario: usuario, role: 'user' },
                process.env.JWT_SECRET,
                { expiresIn: '7d' }
            );
            
            res.json({
                token,
                usuario: {
                    id: usuarioId,
                    usuario: usuario,
                    role: 'user',
                    horas_restantes: 0
                }
            });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Error en el servidor' });
        }
    }
);

app.post('/api/login', 
    body('usuario').notEmpty().trim().escape(),
    body('password').notEmpty(),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { usuario, password } = req.body;
            const usuarios = await pool.query(
                'SELECT * FROM usuarios WHERE usuario = $1',
                [usuario]
            );
            
            if (usuarios.rows.length === 0) {
                return res.status(401).json({ error: 'Credenciales inválidas' });
            }
            
            const user = usuarios.rows[0];
            const passwordValido = await bcrypt.compare(password, user.password);
            if (!passwordValido) {
                return res.status(401).json({ error: 'Credenciales inválidas' });
            }
            
            const tiempoResult = await pool.query(
                'SELECT horas_restantes FROM tiempo_uso WHERE usuario_id = $1',
                [user.id]
            );
            
            const horas_restantes = tiempoResult.rows[0]?.horas_restantes || 0;
            const token = jwt.sign(
                { id: user.id, usuario: user.usuario, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: '7d' }
            );
            
            res.json({
                token,
                usuario: {
                    id: user.id,
                    usuario: user.usuario,
                    role: user.role,
                    alias: user.alias_tarjeta,
                    horas_restantes: parseFloat(horas_restantes)
                }
            });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Error en el servidor' });
        }
    }
);

app.get('/api/tiempo', verificarToken, async (req, res) => {
    try {
        if (req.usuarioRole === 'admin') {
            return res.json({
                horas_restantes: 999999,
                en_pausa: false
            });
        }

        const result = await pool.query(
            'SELECT horas_restantes, ultima_actividad, en_pausa FROM tiempo_uso WHERE usuario_id = $1',
            [req.usuarioId]
        );
        
        if (!result.rows[0]) {
            return res.json({ horas_restantes: 0, en_pausa: false });
        }

        let { horas_restantes, ultima_actividad, en_pausa } = result.rows[0];
        
        if (!en_pausa && ultima_actividad) {
            const ahora = new Date();
            const ultima = new Date(ultima_actividad);
            
            if (!isNaN(ultima.getTime())) {
                const diferencia = ahora - ultima;
                
                if (!isNaN(diferencia) && diferencia > 0) {
                    const segundosPasados = Math.floor(diferencia / 1000);
                    const horasPasadas = segundosPasados / 3600;
                    
                    horas_restantes = Math.max(0, parseFloat(horas_restantes) - horasPasadas);
                    
                    console.log(`Usuario ${req.usuarioId}: pasaron ${segundosPasados}s, restando ${horasPasadas.toFixed(4)} horas`);
                    
                    await pool.query(
                        `UPDATE tiempo_uso 
                         SET horas_restantes = $1, 
                             ultima_actividad = NOW() 
                         WHERE usuario_id = $2`,
                        [horas_restantes, req.usuarioId]
                    );
                }
            }
        }

        const horasValidas = !isNaN(parseFloat(horas_restantes)) ? parseFloat(horas_restantes) : 0;

        res.json({ 
            horas_restantes: horasValidas, 
            en_pausa 
        });
    } catch (error) {
        console.error('Error en /api/tiempo:', error);
        res.status(500).json({ error: 'Error al obtener tiempo' });
    }
});

app.post('/api/tiempo/sincronizar', 
    verificarToken,
    body('horas_restantes').isFloat({ min: 0, max: 999999 }),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { horas_restantes } = req.body;
            const tiempoValido = Math.max(0, parseFloat(horas_restantes) || 0);
            
            await pool.query(
                `UPDATE tiempo_uso 
                 SET horas_restantes = $1,
                     ultima_actividad = NOW()
                 WHERE usuario_id = $2`,
                [tiempoValido, req.usuarioId]
            );
            
            res.json({ 
                success: true, 
                tiempo_actualizado: tiempoValido
            });
        } catch (error) {
            console.error('Error sincronizando tiempo:', error);
            res.status(500).json({ error: 'Error al sincronizar tiempo' });
        }
    }
);

app.post('/api/solicitar-compra', 
    verificarToken,
    body('horas').isInt({ min: 1, max: 1000 }),
    body('monto').isInt({ min: 1000 }),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { horas, monto } = req.body;
            
            await pool.query(
                `INSERT INTO solicitudes_compra (usuario_id, pack_horas, pack_monto, estado)
                 VALUES ($1, $2, $3, 'pendiente')`,
                [req.usuarioId, horas, monto]
            );
            
            res.json({ success: true, message: 'Solicitud enviada' });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Error al crear solicitud' });
        }
    }
);

app.get('/api/admin/usuarios', verificarToken, verificarAdmin, async (req, res) => {
    try {
        const usuarios = await pool.query(`
            SELECT u.id, u.usuario, u.role, u.alias_tarjeta, u.activo,
                   tu.horas_restantes, tu.en_pausa, tu.tiempo_total_usado,
                   COALESCE(SUM(tc.horas_compradas), 0) as horas_compradas_total,
                   COALESCE(SUM(tc.monto_pagado), 0) as total_gastado
            FROM usuarios u
            LEFT JOIN tiempo_uso tu ON u.id = tu.usuario_id
            LEFT JOIN tiempo_compras tc ON u.id = tc.usuario_id
            WHERE u.role != 'admin'
            GROUP BY u.id, tu.horas_restantes, tu.en_pausa, tu.tiempo_total_usado
            ORDER BY u.id DESC
        `);
        res.json(usuarios.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener usuarios' });
    }
});

app.get('/api/admin/estadisticas-ventas', verificarToken, verificarAdmin, async (req, res) => {
    try {
        const porDia = await pool.query(`
            SELECT 
                TO_CHAR(fecha_aprobacion, 'Day') as dia,
                COUNT(*) as total_compras,
                SUM(pack_horas) as total_horas,
                SUM(pack_monto) as total_monto
            FROM solicitudes_compra 
            WHERE estado = 'aprobado' 
                AND fecha_aprobacion IS NOT NULL
                AND fecha_aprobacion >= NOW() - INTERVAL '30 days'
            GROUP BY TO_CHAR(fecha_aprobacion, 'Day')
        `);
        
        const ordenDias = {
            'Monday': 1, 'Tuesday': 2, 'Wednesday': 3,
            'Thursday': 4, 'Friday': 5, 'Saturday': 6, 'Sunday': 7
        };
        
        porDia.rows.sort((a, b) => ordenDias[a.dia.trim()] - ordenDias[b.dia.trim()]);
        
        const porHora = await pool.query(`
            SELECT 
                EXTRACT(HOUR FROM fecha_aprobacion) as hora,
                COUNT(*) as total_compras,
                SUM(pack_horas) as total_horas,
                SUM(pack_monto) as total_monto
            FROM solicitudes_compra 
            WHERE estado = 'aprobado' 
                AND fecha_aprobacion IS NOT NULL
                AND fecha_aprobacion >= NOW() - INTERVAL '30 days'
            GROUP BY EXTRACT(HOUR FROM fecha_aprobacion)
            ORDER BY hora ASC
        `);
        
        const totales = await pool.query(`
            SELECT 
                COUNT(*) as total_compras,
                SUM(pack_horas) as total_horas,
                SUM(pack_monto) as total_monto
            FROM solicitudes_compra 
            WHERE estado = 'aprobado' 
                AND fecha_aprobacion IS NOT NULL
                AND fecha_aprobacion >= NOW() - INTERVAL '30 days'
        `);
        
        let diaPico = null;
        let maxCompras = 0;
        porDia.rows.forEach(d => {
            if (parseInt(d.total_compras) > maxCompras) {
                maxCompras = parseInt(d.total_compras);
                diaPico = d.dia.trim();
            }
        });
        
        let horaPico = null;
        maxCompras = 0;
        porHora.rows.forEach(h => {
            if (parseInt(h.total_compras) > maxCompras) {
                maxCompras = parseInt(h.total_compras);
                horaPico = h.hora;
            }
        });
        
        const traduccionDias = {
            'Monday': 'Lunes', 'Tuesday': 'Martes', 'Wednesday': 'Miércoles',
            'Thursday': 'Jueves', 'Friday': 'Viernes', 'Saturday': 'Sábado', 'Sunday': 'Domingo'
        };

        const porDiaTraducido = porDia.rows.map(d => ({
            dia: d.dia.trim(),
            dia_esp: traduccionDias[d.dia.trim()] || d.dia.trim(),
            total_compras: parseInt(d.total_compras),
            total_horas: parseInt(d.total_horas),
            total_monto: parseInt(d.total_monto)
        }));

        res.json({
            por_dia: porDiaTraducido,
            por_hora: porHora.rows.map(h => ({
                hora: parseInt(h.hora),
                total_compras: parseInt(h.total_compras),
                total_horas: parseInt(h.total_horas),
                total_monto: parseInt(h.total_monto)
            })),
            totales: {
                total_compras: parseInt(totales.rows[0].total_compras),
                total_horas: parseInt(totales.rows[0].total_horas),
                total_monto: parseInt(totales.rows[0].total_monto)
            },
            insights: {
                dia_pico: traduccionDias[diaPico] || diaPico,
                hora_pico: horaPico,
                total_dias_con_datos: porDia.rows.length,
                total_horas_con_datos: porHora.rows.length
            }
        });
    } catch (error) {
        console.error('Error obteniendo estadísticas:', error);
        res.status(500).json({ error: 'Error al obtener estadísticas' });
    }
});

app.post('/api/admin/agregar-horas', 
    verificarToken, 
    verificarAdmin,
    body('usuario_id').isInt(),
    body('horas').isFloat({ min: 0.1 }),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { usuario_id, horas } = req.body;
            
            await pool.query(
                `UPDATE tiempo_uso 
                 SET horas_restantes = horas_restantes + $1,
                     ultima_actividad = NOW()
                 WHERE usuario_id = $2`,
                [horas, usuario_id]
            );
            
            await pool.query(
                `INSERT INTO tiempo_compras (usuario_id, horas_compradas, monto_pagado)
                 VALUES ($1, $2, $3)`,
                [usuario_id, horas, 0]
            );
            
            res.json({ success: true });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Error al agregar horas' });
        }
    }
);

app.post('/api/admin/resetear-horas', 
    verificarToken, 
    verificarAdmin,
    body('usuario_id').isInt(),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { usuario_id } = req.body;
            
            await pool.query(
                'UPDATE tiempo_uso SET horas_restantes = 0, ultima_actividad = NOW() WHERE usuario_id = $1',
                [usuario_id]
            );
            
            res.json({ success: true });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Error al resetear horas' });
        }
    }
);

app.post('/api/admin/toggle-usuario',
    verificarToken,
    verificarAdmin,
    body('usuario_id').isInt(),
    body('activo').isBoolean(),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { usuario_id, activo } = req.body;
            
            await pool.query(
                'UPDATE usuarios SET activo = $1 WHERE id = $2',
                [activo, usuario_id]
            );
            
            res.json({ success: true });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Error al actualizar usuario' });
        }
    }
);

app.get('/api/admin/solicitudes', verificarToken, verificarAdmin, async (req, res) => {
    try {
        const solicitudes = await pool.query(`
            SELECT s.*, u.usuario 
            FROM solicitudes_compra s
            JOIN usuarios u ON s.usuario_id = u.id
            WHERE s.estado = 'pendiente'
            ORDER BY s.fecha_solicitud DESC
        `);
        res.json(solicitudes.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener solicitudes' });
    }
});

app.post('/api/admin/aprobar-solicitud',
    verificarToken,
    verificarAdmin,
    body('solicitud_id').isInt(),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { solicitud_id } = req.body;
            
            const solicitud = await pool.query(
                'SELECT * FROM solicitudes_compra WHERE id = $1',
                [solicitud_id]
            );
            
            if (solicitud.rows.length === 0) {
                return res.status(404).json({ error: 'Solicitud no encontrada' });
            }
            
            const { usuario_id, pack_horas, pack_monto } = solicitud.rows[0];
            
            await pool.query(
                `UPDATE tiempo_uso 
                 SET horas_restantes = horas_restantes + $1,
                     ultima_actividad = NOW()
                 WHERE usuario_id = $2`,
                [pack_horas, usuario_id]
            );
            
            await pool.query(
                `INSERT INTO tiempo_compras (usuario_id, horas_compradas, monto_pagado)
                 VALUES ($1, $2, $3)`,
                [usuario_id, pack_horas, pack_monto]
            );
            
            await pool.query(
                `UPDATE solicitudes_compra 
                 SET estado = 'aprobado', fecha_aprobacion = NOW() 
                 WHERE id = $1`,
                [solicitud_id]
            );
            
            res.json({ success: true, message: 'Solicitud aprobada' });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Error al aprobar solicitud' });
        }
    }
);

app.post('/api/admin/rechazar-solicitud',
    verificarToken,
    verificarAdmin,
    body('solicitud_id').isInt(),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { solicitud_id } = req.body;
            
            await pool.query(
                `UPDATE solicitudes_compra SET estado = 'rechazado' WHERE id = $1`,
                [solicitud_id]
            );
            
            res.json({ success: true, message: 'Solicitud rechazada' });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Error al rechazar solicitud' });
        }
    }
);

app.get('/api/admin/stats', verificarToken, verificarAdmin, async (req, res) => {
    try {
        const usuarios = await pool.query('SELECT COUNT(*) as count FROM usuarios WHERE role != $1', ['admin']);
        const activos = await pool.query('SELECT COUNT(*) as count FROM tiempo_uso WHERE horas_restantes > 0');
        const horas = await pool.query('SELECT SUM(horas_compradas) as total FROM tiempo_compras');
        const gastos = await pool.query('SELECT SUM(monto_pagado) as total FROM tiempo_compras');
        
        res.json({
            total_usuarios: parseInt(usuarios.rows[0].count),
            usuarios_activos: parseInt(activos.rows[0].count),
            total_horas_vendidas: parseInt(horas.rows[0].total) || 0,
            total_recaudado: parseInt(gastos.rows[0].total) || 0
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener estadísticas' });
    }
});

app.post('/api/guardar-alias', 
    verificarToken,
    body('alias').isLength({ min: 3, max: 100 }).trim().escape(),
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const { alias } = req.body;
            await pool.query(
                'UPDATE usuarios SET alias_tarjeta = $1 WHERE id = $2',
                [alias, req.usuarioId]
            );
            
            res.json({ success: true, message: 'Alias guardado' });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Error al guardar alias' });
        }
    }
);

app.get('/api/obtener-alias', verificarToken, async (req, res) => {
    try {
        const usuario = await pool.query(
            'SELECT alias_tarjeta FROM usuarios WHERE id = $1',
            [req.usuarioId]
        );
        res.json({ alias: usuario.rows[0]?.alias_tarjeta || '' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al obtener alias' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Servidor corriendo en puerto ${PORT}`);
    console.log(`📁 Base de datos: PostgreSQL - carton_game`);
    console.log(`🔧 Modo: ${process.env.NODE_ENV || 'development'}`);
});
