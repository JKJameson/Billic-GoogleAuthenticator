<?php
class GoogleAuthenticator {
	public $settings = array(
		'description' => 'If your account password is stolen you can be safe at mind with the Google Authenticator module. If enabled on your account, you are protected by two-step verification before being logged in.',
	);
	function MyAccount_submodule() {
		global $billic, $db;
		$auth = $db->q('SELECT `secret`, `enabled` FROM `GoogleAuthenticator` WHERE `userid` = ?', $billic->user['id']);
		$auth = $auth[0];
		if (empty($auth)) { // || array_key_exists('GoogleAuthenticator_Reset', $_POST)
			$db->insert('GoogleAuthenticator', array(
				'userid' => $billic->user['id'],
				'secret' => $this->createSecret() ,
			));
			$auth = $db->q('SELECT `secret`, `enabled` FROM `GoogleAuthenticator` WHERE `userid` = ?', $billic->user['id']);
			$auth = $auth[0];
			if (empty($auth)) {
				err('Failed to create GoogleAuthenticator secret');
			}
		}
		if (isset($_POST['GoogleAuthenticator_Disable'])) {
			$auth['enabled'] = 0;
			$db->q('UPDATE `GoogleAuthenticator` SET `enabled` = ? WHERE `userid` = ?', 0, $billic->user['id']);
			$_SESSION['GoogleAuthenticator'] = true;
			$billic->status = 'updated';
		}
		if (isset($_POST['GoogleAuthenticator_Enable'])) {
			$checkResult = $this->verifyCode($auth['secret'], $_POST['GoogleAuthenticator_OneTime'], 2);
			if ($checkResult) {
				$auth['enabled'] = 1;
				$db->q('UPDATE `GoogleAuthenticator` SET `enabled` = ? WHERE `userid` = ?', 1, $billic->user['id']);
				$_SESSION['GoogleAuthenticator'] = true;
				$billic->status = 'updated';
			} else {
				$billic->error('The number you entered was invalid');
			}
		}
		$billic_domain = $_SERVER['SERVER_NAME'];
		if (substr($billic_domain, 0, 4) == 'www.') {
			$billic_domain = substr($billic_domain, 4);
		}
		$qrCodeUrl = $this->getQRCodeGoogleUrl($billic_domain, $auth['secret']);
		$billic->show_errors();
		echo '<table class="table table-striped"><tr><th colspan="2">Google Authenticator</th></tr><tr><td><img src="' . $qrCodeUrl . '" width="100" height="100"></td><td><h4>Scan this QR Code into Google Authenticator to link your account.</h4>';
		if ($auth['enabled'] == 1) {
			echo '<form method="POST"><div class="alert alert-success" role="alert">Google Authenticator is ENABLED. <input type="submit" name="GoogleAuthenticator_Disable" value="Click here to disable &raquo;" class="btn btn-danger" onClick="return confirm(\'Are you sure you want to disable?\')"></div></form>';
		} else {
			echo '<div class="alert alert-warning" role="alert">Google Authenticator is DISABLED. To enable, please scan the code to the left and enter the generated number below.</div>';
			echo '<form method="POST"><input type="text" class="form-control" name="GoogleAuthenticator_OneTime" placeholder="Enter the number here" style="width: 200px"><input type="submit" name="GoogleAuthenticator_Enable" value="Enable &raquo;" class="btn btn-success">';
		}
		echo '</td></tr></table>';
	}
	function global_before_header() {
		global $billic, $db;
		if (defined('IN_API') || empty($billic->user)) {
			return;
		}
		if (array_key_exists('GoogleAuthenticator', $_SESSION) && $_SESSION['GoogleAuthenticator'] === true) {
			return;
		}
		$auth = $db->q('SELECT `secret`, `enabled`, `history` FROM `GoogleAuthenticator` WHERE `userid` = ?', $billic->user['id']);
		$auth = $auth[0];
		if ($auth['enabled'] == 1 && !empty($auth['secret'])) {
			$error = false;
			if (array_key_exists('GoogleAuthenticator_OneTime', $_POST)) {
				if (empty($_POST['GoogleAuthenticator_OneTime'])) {
					$error = 'The code can not be empty.';
				} else {
					$md5_post = md5($_POST['GoogleAuthenticator_OneTime']);
					$history = json_decode($auth['history'], true);
					if (is_array($history)) {
						foreach ($history as $md5 => $timestamp) {
							if ($timestamp < (time() - 3600)) {
								unset($history[$timestamp]);
							}
							if ($md5 == $md5_post) {
								$error = 'This one-time code was already used';
							}
						}
					}
					if ($error === false) {
						$checkResult = $this->verifyCode($auth['secret'], $_POST['GoogleAuthenticator_OneTime'], 2);
						if ($checkResult) {
							$history[$md5_post] = time();
							$history = json_encode($history);
							$db->q('UPDATE `GoogleAuthenticator` SET `history` = ? WHERE `userid` = ?', $history, $billic->user['id']);
							$_SESSION['GoogleAuthenticator'] = true;
							return;
						} else {
							$error = 'The code you entered was invalid.';
						}
					}
				}
			}
			$billic->disable_content();
			echo '<html><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.4/css/bootstrap.min.css"></head><body>';
			echo '<style>.outer{display:table;position:absolute;height:100%;width:100%}.middle{display:table-cell;vertical-align:middle}.inner{margin-left:auto;margin-right:auto;width:500px}</style>
<!--[if lte IE 7]><style>.outer{display:inline;top:0}.middle{display:inline;top:50%;position:relative}.inner{display:inline;top:-50%;position:relative}</style><![endif]-->';
			echo '<div class="outer"><div class="middle"><div class="inner well"><img src="/Modules/Core/logo-icon.png" style="float:left;padding-right: 5px"><h1>Google Authenticator</h1>';
			echo '<div style="clear:both"></div>';
			echo '<div align="center">';
			if ($error !== false) {
				echo '<div class="alert alert-danger" role="alert">' . $error . '</div>';
			}
			echo '<form method="POST" class="form-inline"><div class="form-group"><label>Enter code:</label> <input type="text" name="GoogleAuthenticator_OneTime" autocomplete="off" class="form-control"></div> <input type="submit" value="Continue &raquo;" class="btn btn-success"></form></div>';
			echo '</table>';
			echo '</div>';
			echo '<div align="center">' . gmdate('M d Y H:i:s') . ' GMT</div>';
			echo '</div></body></html>';
			exit;
		}
	}
	/**
	 * Create new secret.
	 * 16 characters, randomly chosen from the allowed base32 characters.
	 *
	 * @param int $secretLength
	 * @return string
	 */
	public function createSecret($secretLength = 16) {
		$validChars = $this->_getBase32LookupTable();
		unset($validChars[32]);
		$secret = '';
		for ($i = 0;$i < $secretLength;$i++) {
			$secret.= $validChars[array_rand($validChars) ];
		}
		return $secret;
	}
	/**
	 * Calculate the code, with given secret and point in time
	 *
	 * @param string $secret
	 * @param int|null $timeSlice
	 * @return string
	 */
	public function getCode($secret, $timeSlice = null) {
		if ($timeSlice === null) {
			$timeSlice = floor(time() / 30);
		}
		$codelength = 6;
		$secretkey = $this->_base32Decode($secret);
		// Pack time into binary string
		$time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $timeSlice);
		// Hash it with users secret key
		$hm = hash_hmac('SHA1', $time, $secretkey, true);
		// Use last nipple of result as index/offset
		$offset = ord(substr($hm, -1)) & 0x0F;
		// grab 4 bytes of the result
		$hashpart = substr($hm, $offset, 4);
		// Unpak binary value
		$value = unpack('N', $hashpart);
		$value = $value[1];
		// Only 32 bits
		$value = $value & 0x7FFFFFFF;
		$modulo = pow(10, $codelength);
		return str_pad($value % $modulo, $codelength, '0', STR_PAD_LEFT);
	}
	/**
	 * Get QR-Code URL for image, from google charts
	 *
	 * @param string $name
	 * @param string $secret
	 * @param string $title
	 * @return string
	 */
	public function getQRCodeGoogleUrl($name, $secret, $title = null) {
		$urlencoded = urlencode('otpauth://totp/' . $name . '?secret=' . $secret . '');
		if (isset($title)) {
			$urlencoded.= urlencode('&issuer=' . urlencode($title));
		}
		return 'https://chart.googleapis.com/chart?chs=100x100&chld=M|0&cht=qr&chl=' . $urlencoded . '';
	}
	/**
	 * Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now
	 *
	 * @param string $secret
	 * @param string $code
	 * @param int $discrepancy This is the allowed time drift in 30 second units (8 means 4 minutes before or after)
	 * @param int|null $currentTimeSlice time slice if we want use other that time()
	 * @return bool
	 */
	public function verifyCode($secret, $code, $discrepancy = 1, $currentTimeSlice = null) {
		if ($currentTimeSlice === null) {
			$currentTimeSlice = floor(time() / 30);
		}
		for ($i = - $discrepancy;$i <= $discrepancy;$i++) {
			$calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
			if ($calculatedCode == $code) {
				return true;
			}
		}
		return false;
	}
	/**
	 * Set the code length, should be >=6
	 *
	 * @param int $length
	 * @return PHPGangsta_GoogleAuthenticator
	 */
	public function setCodeLength($length) {
		$this->_codeLength = $length;
		return $this;
	}
	/**
	 * Helper class to decode base32
	 *
	 * @param $secret
	 * @return bool|string
	 */
	protected function _base32Decode($secret) {
		if (empty($secret)) return '';
		$base32chars = $this->_getBase32LookupTable();
		$base32charsFlipped = array_flip($base32chars);
		$paddingCharCount = substr_count($secret, $base32chars[32]);
		$allowedValues = array(
			6,
			4,
			3,
			1,
			0
		);
		if (!in_array($paddingCharCount, $allowedValues)) return false;
		for ($i = 0;$i < 4;$i++) {
			if ($paddingCharCount == $allowedValues[$i] && substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i])) return false;
		}
		$secret = str_replace('=', '', $secret);
		$secret = str_split($secret);
		$binaryString = "";
		for ($i = 0;$i < count($secret);$i = $i + 8) {
			$x = "";
			if (!in_array($secret[$i], $base32chars)) return false;
			for ($j = 0;$j < 8;$j++) {
				$x.= str_pad(base_convert(@$base32charsFlipped[@$secret[$i + $j]], 10, 2) , 5, '0', STR_PAD_LEFT);
			}
			$eightBits = str_split($x, 8);
			for ($z = 0;$z < count($eightBits);$z++) {
				$binaryString.= (($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48) ? $y : "";
			}
		}
		return $binaryString;
	}
	/**
	 * Helper class to encode base32
	 *
	 * @param string $secret
	 * @param bool $padding
	 * @return string
	 */
	protected function _base32Encode($secret, $padding = true) {
		if (empty($secret)) return '';
		$base32chars = $this->_getBase32LookupTable();
		$secret = str_split($secret);
		$binaryString = "";
		for ($i = 0;$i < count($secret);$i++) {
			$binaryString.= str_pad(base_convert(ord($secret[$i]) , 10, 2) , 8, '0', STR_PAD_LEFT);
		}
		$fiveBitBinaryArray = str_split($binaryString, 5);
		$base32 = "";
		$i = 0;
		while ($i < count($fiveBitBinaryArray)) {
			$base32.= $base32chars[base_convert(str_pad($fiveBitBinaryArray[$i], 5, '0') , 2, 10) ];
			$i++;
		}
		if ($padding && ($x = strlen($binaryString) % 40) != 0) {
			if ($x == 8) $base32.= str_repeat($base32chars[32], 6);
			elseif ($x == 16) $base32.= str_repeat($base32chars[32], 4);
			elseif ($x == 24) $base32.= str_repeat($base32chars[32], 3);
			elseif ($x == 32) $base32.= $base32chars[32];
		}
		return $base32;
	}
	/**
	 * Get array with all 32 characters for decoding from/encoding to base32
	 *
	 * @return array
	 */
	protected function _getBase32LookupTable() {
		return array(
			'A',
			'B',
			'C',
			'D',
			'E',
			'F',
			'G',
			'H', //  7
			'I',
			'J',
			'K',
			'L',
			'M',
			'N',
			'O',
			'P', // 15
			'Q',
			'R',
			'S',
			'T',
			'U',
			'V',
			'W',
			'X', // 23
			'Y',
			'Z',
			'2',
			'3',
			'4',
			'5',
			'6',
			'7', // 31
			'='
			// padding char
			
		);
	}
}
