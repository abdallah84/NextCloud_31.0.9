<?php

/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);

namespace Test\Authentication\Login;

use OC\Authentication\Login\ClearLostPasswordTokensCommand;
use OC\Authentication\Login\CompleteLoginCommand;
use OC\Authentication\Login\CreateSessionTokenCommand;
use OC\Authentication\Login\LoggedInCheckCommand;
use OC\Authentication\Login\LoginData;
use OC\Authentication\Login\SetUserTimezoneCommand;
use OC\Authentication\Login\TwoFactorCommand;
use OC\Authentication\Login\UpdateLastPasswordConfirmCommand;
use OC\Authentication\Login\UserDisabledCheckCommand;
use OC\Authentication\Login\UsernameOnlyChain;
use OC\Authentication\Login\UsernameOnlyLoginCommand;
use OC\Authentication\Login\FinishRememberedLoginCommand;
use OC\Authentication\TwoFactorAuth\Manager as TwoFactorManager;
use OC\Authentication\TwoFactorAuth\MandatoryTwoFactor;
use OC\Authentication\TwoFactorAuth\ProviderSet;
use OC\Authentication\Token\IToken;
use OC\Core\Controller\LoginController;
use OC\User\Session;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Authentication\TwoFactorAuth\IProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;
use Psr\Log\LoggerInterface;

class UsernameOnlyChainTest extends TestCase {
        private IRequest|MockObject $request;
        private IUser|MockObject $user;
        private IUserManager|MockObject $userManager;
        private TwoFactorManager|MockObject $twoFactorManager;
        private LoggerInterface|MockObject $commandLogger;
        private LoggerInterface|MockObject $disabledLogger;
        private LoggerInterface|MockObject $loggedInLogger;
        private IEventDispatcher|MockObject $dispatcher;
        private Session|MockObject $session;
        private IConfig|MockObject $config;
        private ISession|MockObject $appSession;
        private MandatoryTwoFactor|MockObject $mandatoryTwoFactor;
        private IURLGenerator|MockObject $urlGenerator;
        private UsernameOnlyChain $chain;

        protected function setUp(): void {
                parent::setUp();

                $this->request = $this->createMock(IRequest::class);
                $this->request->method('getRemoteAddress')->willReturn('127.0.0.1');
                $this->user = $this->createMock(IUser::class);
                $this->userManager = $this->createMock(IUserManager::class);
                $this->twoFactorManager = $this->createMock(TwoFactorManager::class);
                $this->commandLogger = $this->createMock(LoggerInterface::class);
                $this->disabledLogger = $this->createMock(LoggerInterface::class);
                $this->loggedInLogger = $this->createMock(LoggerInterface::class);
                $this->dispatcher = $this->createMock(IEventDispatcher::class);
                $this->session = $this->getMockBuilder(Session::class)
                        ->disableOriginalConstructor()
                        ->onlyMethods(['completeLogin', 'createSessionToken', 'updateTokens', 'createRememberMeToken'])
                        ->getMock();
                $this->config = $this->createMock(IConfig::class);
                $this->appSession = $this->createMock(ISession::class);
                $this->mandatoryTwoFactor = $this->createMock(MandatoryTwoFactor::class);
                $this->urlGenerator = $this->createMock(IURLGenerator::class);

                $usernameOnlyLoginCommand = new UsernameOnlyLoginCommand($this->userManager, $this->twoFactorManager, $this->commandLogger);
                $userDisabledCheckCommand = new UserDisabledCheckCommand($this->userManager, $this->disabledLogger);
                $loggedInCheckCommand = new LoggedInCheckCommand($this->loggedInLogger, $this->dispatcher);
                $completeLoginCommand = new CompleteLoginCommand($this->session);
                $createSessionTokenCommand = new CreateSessionTokenCommand($this->config, $this->session);
                $clearLostPasswordTokensCommand = new ClearLostPasswordTokensCommand($this->config);
                $updateLastPasswordConfirmCommand = new UpdateLastPasswordConfirmCommand($this->appSession);
                $setUserTimezoneCommand = new SetUserTimezoneCommand($this->config, $this->appSession);
                $twoFactorCommand = new TwoFactorCommand($this->twoFactorManager, $this->mandatoryTwoFactor, $this->urlGenerator);
                $finishRememberedLoginCommand = new FinishRememberedLoginCommand($this->session, $this->config);

                $this->chain = new UsernameOnlyChain(
                        $userDisabledCheckCommand,
                        $usernameOnlyLoginCommand,
                        $loggedInCheckCommand,
                        $completeLoginCommand,
                        $createSessionTokenCommand,
                        $clearLostPasswordTokensCommand,
                        $updateLastPasswordConfirmCommand,
                        $setUserTimezoneCommand,
                        $twoFactorCommand,
                        $finishRememberedLoginCommand
                );
        }

        public function testChainFailsWhenTwoFactorUnavailable(): void {
                $loginData = new LoginData($this->request, 'user@example.com', '');

                $this->userManager->expects($this->exactly(2))
                        ->method('get')
                        ->with('user@example.com')
                        ->willReturn(null);
                $this->userManager->expects($this->once())
                        ->method('getByEmail')
                        ->with('user@example.com')
                        ->willReturn([$this->user]);
                $this->user->expects($this->once())
                        ->method('isEnabled')
                        ->willReturn(true);
                $this->twoFactorManager->expects($this->once())
                        ->method('isTwoFactorAuthenticated')
                        ->with($this->user)
                        ->willReturn(false);
                $this->twoFactorManager->expects($this->never())
                        ->method('prepareTwoFactorLogin');

                $result = $this->chain->process($loginData);

                $this->assertFalse($result->isSuccess());
                $this->assertSame(LoginController::LOGIN_MSG_USERNAMEONLY_TWOFA_REQUIRED, $result->getErrorMessage());
        }

        public function testChainRedirectsToTwoFactorChallenge(): void {
                $redirectUrl = '/apps/files';
                $loginData = new LoginData($this->request, 'user@example.com', '', $redirectUrl);

                $this->userManager->expects($this->exactly(2))
                        ->method('get')
                        ->with('user@example.com')
                        ->willReturn(null);
                $this->userManager->expects($this->once())
                        ->method('getByEmail')
                        ->with('user@example.com')
                        ->willReturn([$this->user]);
                $this->user->method('isEnabled')
                        ->willReturn(true);
                $this->user->method('getUID')
                        ->willReturn('resolved-user');
                $this->user->method('getLastLogin')
                        ->willReturn(123);

                $this->twoFactorManager->expects($this->exactly(2))
                        ->method('isTwoFactorAuthenticated')
                        ->with($this->user)
                        ->willReturn(true);
                $this->twoFactorManager->expects($this->once())
                        ->method('prepareTwoFactorLogin')
                        ->with($this->user, true);

                $provider = $this->createMock(IProvider::class);
                $provider->method('getId')->willReturn('dummy');
                $providerSet = new ProviderSet([$provider], false);

                $this->twoFactorManager->expects($this->once())
                        ->method('getProviderSet')
                        ->with($this->user)
                        ->willReturn($providerSet);
                $this->twoFactorManager->expects($this->once())
                        ->method('getLoginSetupProviders')
                        ->with($this->user)
                        ->willReturn([]);

                $this->urlGenerator->expects($this->once())
                        ->method('linkToRoute')
                        ->with('core.TwoFactorChallenge.showChallenge', [
                                'challengeProviderId' => 'dummy',
                                'redirect_url' => $redirectUrl,
                        ])
                        ->willReturn('challenge-url');

                $this->config->expects($this->once())
                        ->method('getSystemValueInt')
                        ->with('remember_login_cookie_lifetime', 60 * 60 * 24 * 15)
                        ->willReturn(60 * 60 * 24 * 15);
                $this->config->expects($this->once())
                        ->method('deleteUserValue')
                        ->with('resolved-user', 'core', 'lostpassword');

                $this->session->expects($this->once())
                        ->method('completeLogin')
                        ->with($this->user, [
                                'loginName' => 'user@example.com',
                                'password' => '',
                        ]);
                $this->session->expects($this->once())
                        ->method('createSessionToken')
                        ->with($this->request, 'resolved-user', 'user@example.com', null, IToken::REMEMBER);
                $this->session->expects($this->once())
                        ->method('updateTokens')
                        ->with('resolved-user', '');
                $this->session->expects($this->never())
                        ->method('createRememberMeToken');

                $this->appSession->expects($this->once())
                        ->method('set')
                        ->with('last-password-confirm', 123);

                $result = $this->chain->process($loginData);

                $this->assertTrue($result->isSuccess());
                $this->assertSame('challenge-url', $result->getRedirectUrl());
                $this->assertSame($this->user, $loginData->getUser());
        }
}
