# php-session
PHPSession is a session storage class for the MySQL backend. It encrypts all session data using openssl and regenerates session IDs on every request.

php-openssl and php-pdo/php-mysql package is needed.

Usage:

<pre>
require_once("class.session.php");
$sess = new PHPSession($PDO_INSTANCE);
$sess->start_session();
</pre>
