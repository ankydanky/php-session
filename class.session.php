<?php

/**
 * PHP DATABASE SESSION STORAGE
 * 
 * @author ANDY KAYL
 * @version 1.1
 * @license http://opensource.org/licenses/BSD-3-Clause
 *
 * Copyright (c) 2016, ANDY KAYL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this list of conditions and
 * the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the <ORGANIZATION> nor the names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

class PHPSession {
	
	private $session_table;
	private $enckey;
	private $sessionid;
	
	/**
	 * CLASS CONSTRUCTOR CLASS
	 */
	
	public function __construct($pdo_instance) {
		$this->db = $pdo_instance;
		$this->session_table = "sessions";
		$this->session_hash = "sha256";
		$this->timeout = 86400; // 86400 = 1 day
		$this->enckey = "this_is_a_default_key_please_change";
		session_set_save_handler(
			array($this, 'open'),
			array($this, 'close'),
			array($this, 'read'),
			array($this, 'write'),
			array($this, 'destroy'),
			array($this, 'gc')
		); 
		register_shutdown_function('session_write_close');
		$this->CreateTable();
	}
	
	/**
	 * SESSION START FUNCTION
	 * @VAR STRING SESSION NAME
	 * @VAR BOOL SECURE HTTPS
	 * @RETURN NONE
	 */
	
	public function start_session($session_name=false, $secure=false) {
		$ua = $_SERVER['HTTP_USER_AGENT'];
		$botpattern = "(";
			$botpattern .= "(bing|yandex|mj12|google|cc|org_|msn|cliqz|twitter)bot";
			$botpattern .= "|ezooms|yahoo|google|robot|spider|crawl(er)?|synapse|cmradar|java|facebook|wordpress";
		$botpattern .= ")";
		if (preg_match("/$botpattern/i", $ua) || empty($ua)) {
			return false;
		}
		$httponly = true;
		if (empty($_SERVER['HTTPS'])) {
			$secure = false;
		}
		if (in_array($this->session_hash, hash_algos())) {
			ini_set('session.hash_function', $this->session_hash);
		}
		ini_set('session.hash_bits_per_character', 5);
		ini_set('session.use_only_cookies', 1);
		ini_set('session.gc_maxlifetime', $this->timeout);
		ini_set('session.gc_probability', 1);
		ini_set('session.gc_divisor', 1);
		$cookieParams = session_get_cookie_params();
		session_set_cookie_params($this->timeout, $cookieParams["path"], $cookieParams["domain"], $secure, $httponly);
		if ($this->sessionid) {
			session_id($this->sessionid);
		}
		if ($session_name !== false) {
			session_name($session_name);
		}
		return session_start();
	}
	
	/**
	 * SET SESSION ID
	 * @var STRING SESSION ID
	 */
	
	public function setSessionId($sessId) {
		$this->sessionid = $sessId;
	}
	
	/**
	 * CREATE TABLE IF NOT EXISTS
	 */
	
	private function CreateTable() {
		$qry_tbl = "CREATE TABLE IF NOT EXISTS `{$this->session_table}` (
			`id` varchar(100),
			`time` int(11),
			`data` text,
			`ip` varchar(15),
			`uagent` varchar(255),
			PRIMARY KEY(`id`)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8";
		$this->db->query($qry_tbl);
	}
	
	/**
	 * OPEN FUNCTION
	 * @VAR NONE
	 * @RETURN BOOL TRUE
	 */
	
	public function open() {
		return true;
	}
	
	/**
	 * SESSION CLOSE FUNCTION
	 * @VAR NONE
	 * @RETURN BOOL TRUE
	 */
	
	public function close() {
		return true;
	}
	
	/**
	 * READ STORED SESSION DATA FROM DATABASE
	 * @VAR STRING SESSION ID
	 * @RETURN STRING SESSION DATA
	 */
	
	public function read($id) {
		$qry = $this->db->prepare("SELECT data FROM {$this->session_table} WHERE id=?");
		$qry->bindValue(1, $id, PDO::PARAM_STR);
		$qry->execute();
		$r_sess = $qry->fetchAll(PDO::FETCH_ASSOC);
		$data = (!empty($r_sess)) ? unserialize($this->decrypt($r_sess[0]['data'])) : "";
		return $data;
	}
	
	/**
	 * WRITE SESSION DATA TO DATABASE
	 * @VAR STRING SESSION ID
	 * @VAR STRING SESSION DATA
	 * @RETURN BOOL TRUE
	 */
	
	public function write($id, $data) {
		$qry = $this->db->prepare("REPLACE INTO {$this->session_table} (id, time, data, ip, uagent) VALUES (?, ?, ?, ?, ?)");
		$qry->bindValue(1, $id, PDO::PARAM_STR);
		$qry->bindValue(2, time(), PDO::PARAM_STR);
		$qry->bindValue(3, $this->encrypt(serialize($data)), PDO::PARAM_STR);
		$qry->bindValue(4, $_SERVER['REMOTE_ADDR'], PDO::PARAM_STR);
		$qry->bindValue(5, $_SERVER['HTTP_USER_AGENT'], PDO::PARAM_STR);
		$qry->execute();
	}
	
	/**
	 * SESSION DESTROY FUNCTION
	 * @VAR STRING SESSION ID
	 * @RETURN BOOL TRUE
	 */
	
	public function destroy($id) {
		$qry = $this->db->prepare("DELETE FROM {$this->session_table} WHERE id=?");
		$qry->bindValue(1, $id, PDO::PARAM_STR);
		$qry->execute();
	}
	
	/**
	 * SESSION GARBAGE COLLECTOR FUNCTION
	 * @VAR INT TIMEOUT IN SECONDS
	 * @RETURN BOOL TRUE
	 */
	
	public function gc($max) {
		$qry = $this->db->prepare("DELETE FROM {$this->session_table} WHERE time<?");
		$qry->bindValue(1, time() - $max, PDO::PARAM_INT);
		$qry->execute();
	}
	
	/**
	 * ENCRYPT SESSION DATA FOR SECURE STORING
	 * @VAR STRING SESSION DATA
	 * @VAR STRING SESSION KEY
	 * @RETURN STRING ECRYPTED DATA
	 */

	private function encrypt($data) {
		$key = hash("sha1", $this->enckey);
		$encrypted = openssl_encrypt($data, "aes-256-ecb", $key, 0);
		return $encrypted;
	}
	
	/**
	 * DECRYPT SESSION DATA FOR SECURE STORING
	 * @VAR STRING SESSION DATA
	 * @VAR STRING SESSION KEY
	 * @RETURN STRING ECRYPTED DATA
	 */
	
	private function decrypt($data) {
		$key = hash("sha1", $this->enckey);
		$decrypted = openssl_decrypt($data, "aes-256-ecb", $key, 0);
		return $decrypted;
	}
	
}

?>
