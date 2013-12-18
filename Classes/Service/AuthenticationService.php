<?php
namespace Aijko\SharepointAuth\Service;

/***************************************************************
 *  Copyright notice
 *
 *  (c) 2013 aijko GmbH <info@aijko.de>
 *
 *  All rights reserved
 *
 *  This script is part of the TYPO3 project. The TYPO3 project is
 *  free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  The GNU General Public License can be found at
 *  http://www.gnu.org/copyleft/gpl.html.
 *
 *  This script is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  This copyright notice MUST APPEAR in all copies of the script!
 ***************************************************************/

/**
 * Class Authentication
 *
 * @package Aijko\SharepointAuth\Service
 */
class AuthenticationService extends \TYPO3\CMS\Sv\AbstractAuthenticationService {

	/**
	 * Authenticate a user (Check various conditions for the user that might invalidate its authentication, eg. password match, domain, IP, etc.)
	 *
	 * @param array $user Data of user.
	 * @return boolean
	 */
	public function authUser(array $user) {
		\t3lib_utility_Debug::debug($user);
	}

	/**
	 * Find a user (eg. look up the user record in database when a login is sent)
	 *
	 * @return mixed User array or FALSE
	 * @todo Define visibility
	 */
	public function getUser() {
		$user = FALSE;
		if ($this->login['status'] == 'login') {
			if ($this->login['uident']) {
				$user = $this->fetchUserRecord($this->login['uname']);
				if (!is_array($user)) {
					// Failed login attempt (no username found)
					$this->writelog(255, 3, 3, 2, 'Login-attempt from %s (%s), username \'%s\' not found!!', array($this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $this->login['uname']));
					// Logout written to log
					\TYPO3\CMS\Core\Utility\GeneralUtility::sysLog(sprintf('Login-attempt from %s (%s), username \'%s\' not found!', $this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $this->login['uname']), 'Core', \TYPO3\CMS\Core\Utility\GeneralUtility::SYSLOG_SEVERITY_WARNING);
				} else {
					if ($this->writeDevLog) {
						\TYPO3\CMS\Core\Utility\GeneralUtility::devLog('User found: ' . \TYPO3\CMS\Core\Utility\GeneralUtility::arrayToLogString($user, array($this->db_user['userid_column'], $this->db_user['username_column'])), 'TYPO3\\CMS\\Sv\\AuthenticationService');
					}
				}
			} else {
				// Failed Login attempt (no password given)
				$this->writelog(255, 3, 3, 2, 'Login-attempt from %s (%s) for username \'%s\' with an empty password!', array($this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $this->login['uname']));
				\TYPO3\CMS\Core\Utility\GeneralUtility::sysLog(sprintf('Login-attempt from %s (%s), for username \'%s\' with an empty password!', $this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $this->login['uname']), 'Core', \TYPO3\CMS\Core\Utility\GeneralUtility::SYSLOG_SEVERITY_WARNING);
			}
		}
		return $user;
	}
}

?>