<?php

declare(strict_types=1);

namespace My2FA\Methods;

use function admin_redirect;
use function flash_message;
use function My2FA\countUserLogs;
use function My2FA\deleteUserMethod;
use function My2FA\insertUserLog;
use function My2FA\insertUserMethod;
use function My2FA\isDeviceTrustingAllowed;
use function My2FA\isRedirectUrlValid;
use function My2FA\isSessionTrusted;
use function My2FA\loadLanguage;
use function My2FA\selectUserLogs;
use function My2FA\setAdminSessionTrusted;
use function My2FA\setDeviceTrusted;
use function My2FA\setSessionTrusted;
use function My2FA\setting;

abstract class AbstractMethod
{
    public const METHOD_ID = 0;

    public const ORDER = 22;

    protected static $definitions = [
        'name' => null,
        'description' => null
    ];

    public static function getDefinitions(): array
    {
        return static::$definitions;
    }

    abstract public static function handleVerification(
        array $user,
        string $verificationUrl,
        array $viewParams = []
    ): string;

    public static function handleActivation(array $user, string $setupUrl, array $viewParams = []): string
    {
        return '';
    }

    public static function handleDeactivation(array $user, string $setupUrl, array $viewParams = []): string
    {
        return '';
    }

    public static function handleManagement(array $user, string $setupUrl, array $viewParams = []): string
    {
        return '';
    }

    public static function canBeActivated(): bool
    {
        return true;
    }

    public static function canBeDeactivated(): bool
    {
        return true;
    }

    public static function canBeManaged(): bool
    {
        return false;
    }

    final protected static function hasUserReachedMaximumAttempts(int $userId): bool
    {
        return
            countUserLogs($userId, 'failed_attempt', 60 * 5)
            >= setting('max_verification_attempts');
    }

    final protected static function recordFailedAttempt(int $userId): void
    {
        insertUserLog([
            'uid' => $userId,
            'event' => 'failed_attempt',
            'data' => [
                'method_id' => static::METHOD_ID
            ]
        ]);
    }

    final protected static function isUserCodeAlreadyUsed(int $userId, string $code, int $secondsInterval): bool
    {
        $userLogs = selectUserLogs($userId, 'succesful_attempt', $secondsInterval);

        foreach ($userLogs as $userLog) {
            if (
                $userLog['data']['method_id'] == static::METHOD_ID &&
                $userLog['data']['code'] == $code
            ) {
                return true;
            }
        }

        return false;
    }

    final protected static function recordSuccessfulAttempt(int $userId, string $code): void
    {
        insertUserLog([
            'uid' => $userId,
            'event' => 'succesful_attempt',
            'data' => [
                'method_id' => static::METHOD_ID,
                'code' => $code
            ]
        ]);
    }

    final protected static function completeVerification(int $userId): void
    {
        global $mybb, $lang;

        loadLanguage();

        $redirectUrl = isRedirectUrlValid($mybb->get_input('redirect_url'))
            ? urldecode($mybb->input['redirect_url'])
            : 'index.php';

        if (
            isDeviceTrustingAllowed() &&
            $mybb->get_input('trust_device') === '1'
        ) {
            setDeviceTrusted($userId);
        }

        if (defined('IN_ADMINCP')) {
            setAdminSessionTrusted();

            flash_message($lang->my2fa_verified_success, 'success');
            admin_redirect($redirectUrl);
        } else {
            setSessionTrusted();

            \My2FA\redirect($redirectUrl, $lang->my2fa_verified_success);
        }
    }

    final protected static function completeActivation(int $userId, string $setupUrl, array $userMethodData = []): void
    {
        global $lang;

        if (!isSessionTrusted()) {
            setSessionTrusted();
        }

        $insertData = [
            'userID' => $userId,
            'methodID' => static::METHOD_ID,
            'methodData' => $userMethodData
        ];

        $hookArguments = [
            'insertData' => &$insertData,
        ];

        $hookArguments = \My2FA\hooksRun('complete_activation', $hookArguments);

        insertUserMethod([
            'uid' => $userId,
            'method_id' => static::METHOD_ID,
            'data' => $userMethodData
        ]);

        \My2FA\redirect($setupUrl, $lang->my2fa_activated_success);
    }

    final protected static function completeDeactivation(int $userId, string $setupUrl): void
    {
        global $lang;

        deleteUserMethod($userId, static::METHOD_ID);
        \My2FA\redirect($setupUrl, $lang->my2fa_deactivated_success);
    }
}
