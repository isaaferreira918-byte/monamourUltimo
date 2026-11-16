<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');

function responder(int $codigo, array $datos): void
{
    http_response_code($codigo);
    echo json_encode($datos, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

$https = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'httponly' => true,
    'secure' => $https,
    'samesite' => 'Lax',
    'path' => '/',
]);

if (!session_start()) {
    error_log('No se pudo iniciar la sesión de cuenta.');
    responder(500, ['ok' => false, 'message' => 'No se pudo iniciar la sesión. Intentá nuevamente.']);
}

if (!isset($_SESSION['account_csrf']) || !is_string($_SESSION['account_csrf'])) {
    $_SESSION['account_csrf'] = bin2hex(random_bytes(32));
}

$metodo = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($metodo === 'GET') {
    $usuario = isset($_SESSION['account_user']) && is_array($_SESSION['account_user'])
        ? $_SESSION['account_user']
        : null;

    responder(200, [
        'ok' => true,
        'csrfToken' => $_SESSION['account_csrf'],
        'user' => $usuario ? ['name' => $usuario['name'], 'email' => $usuario['email']] : null,
    ]);
}

if ($metodo !== 'POST') {
    header('Allow: GET, POST');
    responder(405, ['ok' => false, 'message' => 'Método no permitido.']);
}

$tokenEnviado = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
if (!is_string($tokenEnviado) || !hash_equals($_SESSION['account_csrf'], $tokenEnviado)) {
    responder(403, ['ok' => false, 'message' => 'La sesión venció. Cerrá y volvé a abrir el panel de cuenta.']);
}

try {
    $entrada = json_decode((string) file_get_contents('php://input'), true, 512, JSON_THROW_ON_ERROR);
} catch (JsonException $error) {
    responder(400, ['ok' => false, 'message' => 'No se pudo leer el formulario. Revisá los datos e intentá nuevamente.']);
}

if (!is_array($entrada) || !isset($entrada['action']) || !is_string($entrada['action'])) {
    responder(400, ['ok' => false, 'message' => 'La solicitud no tiene un formato válido.']);
}

$accion = $entrada['action'];
if (!in_array($accion, ['register', 'login', 'logout'], true)) {
    responder(400, ['ok' => false, 'message' => 'La acción solicitada no es válida.']);
}

$directorioDatos = getenv('MONAMOUR_PRIVATE_DIR');
if ($directorioDatos === false || $directorioDatos === '') {
    $directorioDatos = sys_get_temp_dir()
        . DIRECTORY_SEPARATOR
        . 'monamour-private-data-'
        . hash('sha256', dirname(__DIR__));
}

if (!is_dir($directorioDatos) && !mkdir($directorioDatos, 0700, true) && !is_dir($directorioDatos)) {
    error_log('No se pudo crear el directorio privado de cuentas: ' . $directorioDatos);
    responder(500, ['ok' => false, 'message' => 'No se pudo preparar el almacenamiento de cuentas. Revisá los permisos del servidor.']);
}

if (!is_writable($directorioDatos)) {
    error_log('El directorio privado de cuentas no tiene permisos de escritura: ' . $directorioDatos);
    responder(500, ['ok' => false, 'message' => 'El almacenamiento de cuentas no tiene permisos de escritura.']);
}

try {
    $base = new PDO('sqlite:' . $directorioDatos . DIRECTORY_SEPARATOR . 'accounts.sqlite', null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $base->exec('PRAGMA busy_timeout = 5000');
    $base->exec(
        'CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )'
    );

    if ($accion === 'logout') {
        unset($_SESSION['account_user']);
        session_regenerate_id(true);
        $_SESSION['account_csrf'] = bin2hex(random_bytes(32));
        responder(200, ['ok' => true, 'message' => 'Cerraste sesión correctamente.', 'user' => null, 'csrfToken' => $_SESSION['account_csrf']]);
    }

    $email = isset($entrada['email']) && is_string($entrada['email'])
        ? strtolower(trim($entrada['email']))
        : '';
    $contrasena = isset($entrada['password']) && is_string($entrada['password'])
        ? $entrada['password']
        : '';

    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
        responder(422, ['ok' => false, 'message' => 'Ingresá un email válido.']);
    }
    if (strlen($contrasena) < 8 || strlen($contrasena) > 72) {
        responder(422, ['ok' => false, 'message' => 'La contraseña debe tener entre 8 y 72 caracteres.']);
    }

    if ($accion === 'register') {
        $nombre = isset($entrada['name']) && is_string($entrada['name'])
            ? trim($entrada['name'])
            : '';

        if (strlen($nombre) < 2 || strlen($nombre) > 80) {
            responder(422, ['ok' => false, 'message' => 'El nombre debe tener entre 2 y 80 caracteres.']);
        }

        $buscar = $base->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
        $buscar->execute(['email' => $email]);
        if ($buscar->fetch()) {
            responder(409, ['ok' => false, 'message' => 'Ya existe una cuenta con ese email. Iniciá sesión.']);
        }

        $guardar = $base->prepare('INSERT INTO users (name, email, password_hash) VALUES (:name, :email, :password_hash)');
        $guardar->execute([
            'name' => $nombre,
            'email' => $email,
            'password_hash' => password_hash($contrasena, PASSWORD_DEFAULT),
        ]);
        $usuario = ['id' => (int) $base->lastInsertId(), 'name' => $nombre, 'email' => $email];
    } else {
        $buscar = $base->prepare('SELECT id, name, email, password_hash FROM users WHERE email = :email LIMIT 1');
        $buscar->execute(['email' => $email]);
        $registro = $buscar->fetch();

        if (!$registro || !password_verify($contrasena, $registro['password_hash'])) {
            responder(401, ['ok' => false, 'message' => 'El email o la contraseña no son correctos.']);
        }

        $usuario = ['id' => (int) $registro['id'], 'name' => $registro['name'], 'email' => $registro['email']];
    }

    session_regenerate_id(true);
    $_SESSION['account_user'] = $usuario;
    $_SESSION['account_csrf'] = bin2hex(random_bytes(32));

    responder(200, [
        'ok' => true,
        'message' => $accion === 'register' ? 'Tu cuenta se creó correctamente.' : 'Iniciaste sesión correctamente.',
        'user' => ['name' => $usuario['name'], 'email' => $usuario['email']],
        'csrfToken' => $_SESSION['account_csrf'],
    ]);
} catch (PDOException $error) {
    error_log('Error de base de datos en cuentas: ' . $error->getMessage());
    responder(500, ['ok' => false, 'message' => 'No se pudo completar la operación. Revisá que PHP tenga PDO_SQLite habilitado e intentá de nuevo.']);
}
