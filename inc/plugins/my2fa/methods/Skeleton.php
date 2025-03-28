<?php

declare(strict_types=1);

namespace My2FA\Methods;

use function My2FA\selectMethods;
use function My2FA\selectUserMethods;
use function My2FA\template;

class Skeleton extends AbstractMethod
{
    public const METHOD_ID = 22;

    protected static $definitions = [
        'name' => 'Skeleton',
        'description' => 'A implementation sample of a 2FA method.',
    ];

    public static function handleVerification(array $user, string $verificationUrl, array $viewParams = []): string
    {
        global $mybb, $lang, $theme;

        extract($viewParams);

        $userID = (int)$user['uid'];

        $method = selectMethods()[self::METHOD_ID];
        $userMethod = selectUserMethods($userID, (array)self::METHOD_ID)[self::METHOD_ID];

        if (self::hasUserReachedMaximumAttempts($userID)) {
            $errors = inline_error((array)$lang->my2fa_verification_blocked_error);
        } elseif (isset($mybb->input['otp'])) {
            if (self::isOtpValid($mybb->input['otp'])) {
                self::completeVerification($userID);
            } else {
                self::recordFailedAttempt($userID);

                $errors = self::hasUserReachedMaximumAttempts($userID)
                    ? inline_error((array)$lang->my2fa_verification_blocked_error)
                    : inline_error((array)$lang->my2fa_code_error);
            }
        }

        return eval(template('method_skeleton_verification'));
    }

    public static function handleActivation(array $user, string $setupUrl, array $viewParams = []): string
    {
        global $mybb, $lang, $theme;

        extract($viewParams);

        $method = selectMethods()[self::METHOD_ID];

        if (isset($mybb->input['otp'])) {
            if (self::isOtpValid($mybb->input['otp'])) {
                self::completeActivation((int)$user['uid'], $setupUrl);
            } else {
                $errors = inline_error((array)$lang->my2fa_code_error);
            }
        }

        return eval(template('method_skeleton_activation'));
    }

    public static function handleDeactivation(array $user, string $setupUrl, array $viewParams = []): string
    {
        self::completeDeactivation((int)$user['uid'], $setupUrl);

        return '';
    }

    private static function isOtpValid(string $otp): bool
    {
        return (int)$otp === 123;
    }
}
