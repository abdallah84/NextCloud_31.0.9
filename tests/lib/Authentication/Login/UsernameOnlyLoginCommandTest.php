<?php

/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);

namespace Test\Authentication\Login;

use OC\Authentication\Login\LoginData;
use OC\Authentication\Login\UsernameOnlyLoginCommand;
use OC\Authentication\TwoFactorAuth\Manager as TwoFactorManager;
use OC\Core\Controller\LoginController;
use OCP\IUser;
use OCP\IUserManager;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

class UsernameOnlyLoginCommandTest extends ALoginTestCommand {
        private const LOGIN_NAME = 'user@example.com';

        /** @var IUserManager|MockObject */
        private $userManager;

        /** @var TwoFactorManager|MockObject */
        private $twoFactorManager;

        /** @var LoggerInterface|MockObject */
        private $logger;

        /** @var IUser|MockObject */
        private $resolvedUser;

        protected function setUp(): void {
                parent::setUp();

                $this->userManager = $this->createMock(IUserManager::class);
                $this->twoFactorManager = $this->createMock(TwoFactorManager::class);
                $this->logger = $this->createMock(LoggerInterface::class);
                $this->resolvedUser = $this->createMock(IUser::class);

                $this->cmd = new UsernameOnlyLoginCommand(
                        $this->userManager,
                        $this->twoFactorManager,
                        $this->logger
                );
        }

        public function testProcessFailsWhenUserCannotBeResolved(): void {
                $data = new LoginData($this->request, self::LOGIN_NAME, '');

                $this->userManager->expects($this->once())
                        ->method('get')
                        ->with(self::LOGIN_NAME)
                        ->willReturn(null);
                $this->userManager->expects($this->once())
                        ->method('getByEmail')
                        ->with(self::LOGIN_NAME)
                        ->willReturn([]);
                $this->twoFactorManager->expects($this->never())
                        ->method('isTwoFactorAuthenticated');

                $result = $this->cmd->process($data);

                $this->assertFalse($result->isSuccess());
                $this->assertSame(LoginController::LOGIN_MSG_USERNAMEONLY_ACCOUNT_UNAVAILABLE, $result->getErrorMessage());
                $this->assertFalse($data->getUser());
        }

        public function testProcessFailsForDisabledUser(): void {
                $data = new LoginData($this->request, 'user123', '');

                $this->userManager->expects($this->once())
                        ->method('get')
                        ->with('user123')
                        ->willReturn($this->resolvedUser);
                $this->resolvedUser->expects($this->once())
                        ->method('isEnabled')
                        ->willReturn(false);
                $this->twoFactorManager->expects($this->never())
                        ->method('isTwoFactorAuthenticated');

                $result = $this->cmd->process($data);

                $this->assertFalse($result->isSuccess());
                $this->assertSame(LoginController::LOGIN_MSG_USERNAMEONLY_ACCOUNT_UNAVAILABLE, $result->getErrorMessage());
                $this->assertFalse($data->getUser());
        }

        public function testProcessFailsWithoutTwoFactorProviders(): void {
                $data = new LoginData($this->request, self::LOGIN_NAME, '');

                $this->userManager->expects($this->once())
                        ->method('get')
                        ->with(self::LOGIN_NAME)
                        ->willReturn(null);
                $this->userManager->expects($this->once())
                        ->method('getByEmail')
                        ->with(self::LOGIN_NAME)
                        ->willReturn([$this->resolvedUser]);
                $this->resolvedUser->method('isEnabled')
                        ->willReturn(true);
                $this->twoFactorManager->expects($this->once())
                        ->method('isTwoFactorAuthenticated')
                        ->with($this->resolvedUser)
                        ->willReturn(false);

                $result = $this->cmd->process($data);

                $this->assertFalse($result->isSuccess());
                $this->assertSame(LoginController::LOGIN_MSG_USERNAMEONLY_TWOFA_REQUIRED, $result->getErrorMessage());
                $this->assertFalse($data->getUser());
        }

        public function testProcessSucceeds(): void {
                $data = new LoginData($this->request, self::LOGIN_NAME, '');

                $this->userManager->expects($this->once())
                        ->method('get')
                        ->with(self::LOGIN_NAME)
                        ->willReturn(null);
                $this->userManager->expects($this->once())
                        ->method('getByEmail')
                        ->with(self::LOGIN_NAME)
                        ->willReturn([$this->resolvedUser]);
                $this->resolvedUser->method('isEnabled')
                        ->willReturn(true);
                $this->twoFactorManager->expects($this->once())
                        ->method('isTwoFactorAuthenticated')
                        ->with($this->resolvedUser)
                        ->willReturn(true);

                $result = $this->cmd->process($data);

                $this->assertTrue($result->isSuccess());
                $this->assertSame($this->resolvedUser, $data->getUser());
        }
}
