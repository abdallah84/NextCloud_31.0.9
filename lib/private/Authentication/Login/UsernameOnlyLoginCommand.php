<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
namespace OC\Authentication\Login;

use OC\Authentication\TwoFactorAuth\Manager as TwoFactorManager;
use OC\Core\Controller\LoginController;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Util;
use Psr\Log\LoggerInterface;

class UsernameOnlyLoginCommand extends ALoginCommand {
        public function __construct(
                private IUserManager $userManager,
                private TwoFactorManager $twoFactorManager,
                private LoggerInterface $logger
        ) {
        }

        public function process(LoginData $loginData): LoginResult {
                $originalLoginName = $loginData->getUsername();
                $lookupLoginName = $originalLoginName;

                Util::emitHook(
                        '\\OCA\\Files_Sharing\\API\\Server2Server',
                        'preLoginNameUsedAsUserName',
                        ['uid' => &$lookupLoginName],
                );

                $user = $this->resolveUser($lookupLoginName, $originalLoginName);
                if ($user === null) {
                        $this->logger->warning(
                                sprintf(
                                        "Passwordless login failed: '%s' not found (Remote IP: %s)",
                                        $originalLoginName,
                                        $loginData->getRequest()->getRemoteAddress(),
                                ),
                                ['app' => 'core'],
                        );
                        $loginData->setUser(false);
                        return LoginResult::failure($loginData, LoginController::LOGIN_MSG_USERNAMEONLY_ACCOUNT_UNAVAILABLE);
                }

                if ($user->isEnabled() === false) {
                        $this->logger->warning(
                                sprintf(
                                        "Passwordless login failed: '%s' disabled (Remote IP: %s)",
                                        $originalLoginName,
                                        $loginData->getRequest()->getRemoteAddress(),
                                ),
                                ['app' => 'core'],
                        );
                        $loginData->setUser(false);
                        return LoginResult::failure($loginData, LoginController::LOGIN_MSG_USERNAMEONLY_ACCOUNT_UNAVAILABLE);
                }

                if (!$this->twoFactorManager->isTwoFactorAuthenticated($user)) {
                        $this->logger->info(
                                sprintf(
                                        "Passwordless login rejected: '%s' lacks two-factor providers (Remote IP: %s)",
                                        $originalLoginName,
                                        $loginData->getRequest()->getRemoteAddress(),
                                ),
                                ['app' => 'core'],
                        );
                        $loginData->setUser(false);
                        return LoginResult::failure($loginData, LoginController::LOGIN_MSG_USERNAMEONLY_TWOFA_REQUIRED);
                }

                $loginData->setUser($user);

                return $this->processNextOrFinishSuccessfully($loginData);
        }

        private function resolveUser(string $lookupLoginName, string $originalLoginName): ?IUser {
                $user = $this->userManager->get($lookupLoginName);
                if ($user instanceof IUser) {
                        return $user;
                }

                if (filter_var($lookupLoginName, FILTER_VALIDATE_EMAIL)) {
                        $users = $this->userManager->getByEmail($lookupLoginName);
                        if (count($users) === 1) {
                                $user = $users[0];
                                if ($user instanceof IUser) {
                                        return $user;
                                }
                        }

                        return null;
                }

                if ($lookupLoginName !== $originalLoginName && filter_var($originalLoginName, FILTER_VALIDATE_EMAIL)) {
                        $users = $this->userManager->getByEmail($originalLoginName);
                        if (count($users) === 1) {
                                $user = $users[0];
                                if ($user instanceof IUser) {
                                        return $user;
                                }
                        }
                }

                return null;
        }
}
