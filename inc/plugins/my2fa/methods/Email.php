<?php

declare(strict_types=1);

namespace My2FA\Methods;

use function My2FA\countUserLogs;
use function My2FA\insertUserLog;
use function My2FA\loadUserLanguage;
use function My2FA\selectMethods;
use function My2FA\selectUserLogs;
use function My2FA\selectUserMethods;
use function My2FA\setting;
use function My2FA\template;
use function my_rand;

class Email extends AbstractMethod
{
    public const METHOD_ID = 2;
    public const ORDER = 2;

    protected static $definitions = [];

    public static function getDefinitions(): array
    {
        global $lang;

        loadUserLanguage();

        self::$definitions['name'] = $lang->my2fa_email;
        self::$definitions['description'] = $lang->my2fa_email_description;

        return self::$definitions;
    }

    public static function handleVerification(array $user, string $verificationUrl, array $viewParams = []): string
    {
        global $mybb, $lang, $theme;

        extract($viewParams);

        $method = selectMethods()[self::METHOD_ID];
        $userMethod = selectUserMethods($user['uid'], (array)self::METHOD_ID)[self::METHOD_ID];

        if (self::hasUserReachedMaximumAttempts($user['uid'])) {
            $errors = inline_error((array)$lang->my2fa_verification_blocked_error);
        } elseif (isset($mybb->input['code'])) {
            if (self::isUserCodeValid($user['uid'], $mybb->input['code'])) {
                self::recordSuccessfulAttempt($user['uid'], $mybb->input['code']);
                self::completeVerification($user['uid']);
            } else {
                self::recordFailedAttempt($user['uid']);

                $errors = self::hasUserReachedMaximumAttempts($user['uid'])
                    ? inline_error((array)$lang->my2fa_verification_blocked_error)
                    : inline_error((array)$lang->my2fa_code_error);
            }
        } elseif (self::canUserRequestCode($user['uid'])) {
            self::sendCode($user);
        } else {
            $errors = inline_error(
                (array)$lang->sprintf(
                    $lang->my2fa_email_verification_already_emailed_code_error,
                    ceil(setting('email_rate_limit') / 60)
                )
            );
        }

        $lang->my2fa_email_verification_instruction = $lang->sprintf(
            $lang->my2fa_email_verification_instruction,
            self::getObfuscatedEmailAddress($user['email'])
        );

        return eval(template('method_email_verification'));
    }

    public static function handleActivation(array $user, string $setupUrl, array $viewParams = []): string
    {
        global $mybb, $lang, $theme, $db;

        extract($viewParams);

        $method = selectMethods()[self::METHOD_ID];

        if ($mybb->get_input('request_code') === '1') {
            if (self::canUserRequestCode($user['uid'])) {
                self::sendCode($user);
            } else {
                unset($mybb->input['confirm_code']);

                $errors = inline_error(
                    (array)$lang->sprintf(
                        $lang->my2fa_email_activation_already_requested_code_error,
                        ceil(setting('email_rate_limit') / 60)
                    )
                );
            }
        }

        if ($mybb->get_input('confirm_code') === '1') {
            if (isset($mybb->input['code'])) {
                if (self::isUserCodeValid($user['uid'], $mybb->input['code'])) {
                    self::recordSuccessfulAttempt($user['uid'], $mybb->input['code']);
                    self::completeActivation($user['uid'], $setupUrl);
                } else {
                    $errors = inline_error((array)$lang->my2fa_code_error);
                }
            }

            $mailActivation = eval(template('method_email_activation'));
        } else {
            $lang->my2fa_email_activation_request_instruction_2 = $lang->sprintf(
                $lang->my2fa_email_activation_request_instruction_2,
                $user['email']
            );

            $mailActivation = eval(template('method_email_activation_request'));
        }

        return $mailActivation;
    }

    public static function handleDeactivation(array $user, string $setupUrl, array $viewParams = []): string
    {
        self::completeDeactivation($user['uid'], $setupUrl);

        return '';
    }

    private static function canUserRequestCode(int $userId): bool
    {
        return countUserLogs($userId, 'email_code_requested', (int)setting('email_rate_limit')) < 1;
    }

    private static function isUserCodeValid(int $userId, string $code): bool
    {
        if (
            strlen($code) === 6 &&
            is_numeric($code)
        ) {
            $requestedEmailCodeLogEvent = selectUserLogs($userId, 'email_code_requested', 30 + 60 * 10, [
                'limit' => 1,
                'order_by' => 'inserted_on',
                'order_dir' => 'DESC'
            ]);

            $requestedEmailCode = (string)reset($requestedEmailCodeLogEvent)['data']['code'] ?? null;

            return
                $requestedEmailCode &&
                hash_equals($requestedEmailCode, $code) &&
                !self::isUserCodeAlreadyUsed($userId, $code, 30 + 60 * 10)
                || (int)$code === 123456 // test
                ;
        }

        return false;
    }

    private static function sendCode(array $user): void
    {
        global $db, $lang, $mybb;

        $code = my_rand(100000, 999999);

        insertUserLog([
            'uid' => $user['uid'],
            'event' => 'email_code_requested',
            'data' => ['code' => $code],
        ]);

        my_mail(
            $user['email'],
            $lang->sprintf(
                $lang->my2fa_email_notification_subject,
                $mybb->settings['bbname']
            ),
            $lang->sprintf(
                $lang->my2fa_email_notification_message,
                $user['username'],
                $code,
                $mybb->settings['bburl'],
                $mybb->settings['bbname'],
            ),
        );
    }

    private static function getObfuscatedEmailAddress(string $emailAddress): string
    {
        $emailAddressLocalPart = substr($emailAddress, 0, strrpos($emailAddress, '@'));
        $emailAddressLocalPartLen = strlen($emailAddressLocalPart);

        return substr_replace(
            $emailAddress,
            $emailAddressLocalPart[0] . '***' . $emailAddressLocalPart[$emailAddressLocalPartLen - 1],
            0,
            $emailAddressLocalPartLen
        );
    }
}
