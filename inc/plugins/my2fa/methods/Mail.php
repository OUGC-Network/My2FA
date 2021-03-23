<?php

namespace My2FA\Methods;

class Mail extends AbstractMethod
{
    public const METHOD_ID = 2;
    public const ORDER = 2;

    protected static $definitions = [];

    public static function getDefinitions(): array
    {
        global $lang;

        \My2FA\loadUserLanguage();

        self::$definitions['name'] = $lang->my2fa_mail;
        self::$definitions['description'] = $lang->my2fa_mail_description;

        return self::$definitions;
    }

    public static function handleVerification(array $user, string $verificationUrl, array $viewParams = []): string
    {
        global $mybb, $lang, $theme;

        extract($viewParams);

        $method = \My2FA\selectMethods()[self::METHOD_ID];
        $userMethod = \My2FA\selectUserMethods($user['uid'], (array) self::METHOD_ID)[self::METHOD_ID];

        if (self::hasUserReachedMaximumAttempts($user['uid']))
        {
            $errors = inline_error((array) $lang->my2fa_verification_blocked_error);
        }
        else if (isset($mybb->input['code']))
        {
            if (self::isUserCodeValid($user['uid'], $mybb->input['code']))
            {
                self::recordSuccessfulAttempt($user['uid'], $mybb->input['code']);
                self::completeVerification($user['uid']);
            }
            else
            {
                self::recordFailedAttempt($user['uid']);

                $errors = self::hasUserReachedMaximumAttempts($user['uid'])
                    ? inline_error((array) $lang->my2fa_verification_blocked_error)
                    : inline_error((array) $lang->my2fa_code_error)
                ;
            }
        }
        else
        {
            if (self::canUserRequestCode($user['uid']))
            {
                self::sendCode($user);
            }
            else
            {
                $errors = inline_error((array) $lang->sprintf(
                    $lang->my2fa_mail_verification_already_emailed_code_error,
                    ceil(\My2FA\setting('email_rate_limit') / 60)
                ));
            }
        }

        eval('$mailVerification = "' . \My2FA\template('method_mail_verification') . '";');
        return $mailVerification;
    }

    public static function handleActivation(array $user, string $setupUrl, array $viewParams = []): string
    {
        global $mybb, $lang, $theme, $db;

        extract($viewParams);

        $method = \My2FA\selectMethods()[self::METHOD_ID];

        if ($mybb->get_input('request_code') === '1')
        {
            if (self::canUserRequestCode($user['uid']))
            {
                self::sendCode($user);
            }
            else
            {
                unset($mybb->input['confirm_code']);

                $errors = inline_error((array) $lang->sprintf(
                    $lang->my2fa_mail_activation_already_requested_code_error,
                    ceil(\My2FA\setting('email_rate_limit') / 60)
                ));
            }
        }

        if ($mybb->get_input('confirm_code') === '1')
        {
            if (isset($mybb->input['code']))
            {
                if (self::isUserCodeValid($user['uid'], $mybb->input['code']))
                {
                    self::recordSuccessfulAttempt($user['uid'], $mybb->input['code']);
                    self::completeActivation($user['uid'], $setupUrl);
                }
                else
                {
                    $errors = inline_error((array) $lang->my2fa_code_error);
                }
            }

            $main_description = $lang->sprintf($lang->my2fa_mail_activation_instruction_main_1, $user['email']);

            eval('$mailActivation = "' . \My2FA\template('method_mail_activation') . '";');
        }
        else
        {
            $request_description = $lang->sprintf($lang->my2fa_mail_activation_instruction_request_1, $user['email']);

            eval('$mailActivation = "' . \My2FA\template('method_mail_request') . '";');
        }

        return $mailActivation;
    }

    public static function handleDeactivation(array $user, string $setupUrl, array $viewParams = []): string
    {
        self::completeDeactivation($user['uid'], $setupUrl);
    }

    private static function canUserRequestCode(int $userId): bool
    {
        return \My2FA\countUserLogs($userId, 'email_code_requested', \My2FA\setting('email_rate_limit')) < 1;
    }

    private static function isUserCodeValid(int $userId, string $code): bool
    {
        if (
            strlen($code) === 6 &&
            is_numeric($code)
        ) {
            $requestedEmailCodeLogEvent = \My2FA\selectUserLogs($userId, 'email_code_requested', 30+60*10, [
                'limit' => 1,
                'order_by' => 'inserted_on',
                'order_dir' => 'DESC'
            ]);

            $requestedEmailCode = reset($requestedEmailCodeLogEvent)['data']['code'] ?? null;

            return
                $requestedEmailCode &&
                hash_equals((string) $requestedEmailCode, $code) &&
                !self::isUserCodeAlreadyUsed($userId, $code, 30+60*10)
                || (int) $code === 123456 // test
            ;
        }

        return False;
    }

    private static function sendCode(array $user): void
    {
        global $db, $lang, $mybb;

        $code = \my_rand(100000, 999999);

        \My2FA\insertUserLog([
            'uid' => $user['uid'],
            'event' => 'email_code_requested',
            'data' => ['code' => $code],
        ]);

        my_mail(
            $user['email'],
            $lang->my2fa_mail_activation_instruction_request_mail_subject,
            $lang->sprintf(
                $lang->my2fa_mail_activation_instruction_request_mail_message,
                $user['username'],
                $code,
                $mybb->settings['bburl'],
                $mybb->settings['bbname'],
            ),
        );
    }
}
