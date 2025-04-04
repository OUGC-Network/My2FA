<?php

declare(strict_types=1);

namespace My2FA;

function getVerificationForm(
    array $user,
    string $verificationUrl,
    bool $includeBreadcrumb = true,
    bool $includeExtraRows = true
): ?string {
    global $mybb, $lang, $theme;

    $output = null;
    $mybb->input['method'] = $mybb->get_input('method');

    if (!isset($theme)) {
        $theme = getDefaultTheme();
    }

    $methods = selectMethods();
    $userMethods = selectUserMethods((int)$user['uid']);

    // here I can add a check that if usermethods is empty, skip verification
    // but this should not happen if has_my2fa is correctly rebuilt every time

    $redirectUrl = htmlspecialchars_uni($mybb->get_input('redirect_url'));
    $redirectUrlQueryStr = htmlspecialchars_uni(
        redirectUrlAsQueryString(urldecode($mybb->get_input('redirect_url')))
    );

    $user['username_escaped'] = htmlspecialchars_uni($user['username']);

    if (
        isset($methods[$mybb->input['method']]) &&
        isset($userMethods[$mybb->input['method']]) &&
        $mybb->get_input('verify') === '1'
    ) {
        verify_post_check($mybb->get_input('my_post_key'));

        $method = $methods[$mybb->input['method']];

        if ($includeBreadcrumb) {
            add_breadcrumb($lang->my2fa_title, $verificationUrl . $redirectUrlQueryStr);
            add_breadcrumb($method['definitions']['name']);
        }

        $verificationFormButtons = eval(template('verification_form_buttons'));

        $verificationFormTrustDeviceOption = '';

        $verificationTrustDeviceOption = null;
        if (isDeviceTrustingAllowed()) {
            $lang->my2fa_verification_trust_device = $lang->sprintf(
                $lang->my2fa_verification_trust_device,
                setting('device_trusting_duration_in_days')
            );
            $lang->my2fa_verification_trust_device_description = $lang->sprintf(
                $lang->my2fa_verification_trust_device_description,
                setting('device_trusting_duration_in_days')
            );

            $checkboxInputState = 'checked';
            if (isset($mybb->input['trust_device']) && $mybb->input['trust_device'] !== '1') {
                $checkboxInputState = null;
            }

            $verificationFormTrustDeviceOption = eval(template('verification_form_trust_device_option'));
        }

        $output = $method['className']::handleVerification(
            $user,
            $verificationUrl,
            compact(
                'verificationUrl',
                'redirectUrl',
                'redirectUrlQueryStr',
                'verificationFormButtons',
                'verificationFormTrustDeviceOption'
            )
        );
    } else {
        if ($includeBreadcrumb) {
            add_breadcrumb($lang->my2fa_title);
        }

        $verificationMethodRows = null;
        foreach ($userMethods as $userMethod) {
            $method = $methods[$userMethod['method_id']];

            $verificationMethodRows .= eval(template('verification_methods_row'));
        }

        $verificationExtraRows = '';

        if ($includeExtraRows) {
            $verificationExtraRows .= eval(template('verification_extra_rows'));
        }

        $output = eval(template('verification'));
    }

    return $output;
}

#todo: order of activated methods
function getSetupForm(array $user, string $setupUrl, bool $includeBreadcrumb = true): ?string
{
    global $mybb, $lang, $theme;

    $output = null;
    $mybb->input['method'] = $mybb->get_input('method');

    $userID = (int)$user['uid'];

    $methods = selectMethods();
    $userMethods = selectUserMethods($userID);

    if (isset($methods[$mybb->input['method']])) {
        verify_post_check($mybb->get_input('my_post_key'));

        $method = $methods[$mybb->input['method']];

        if (
            $mybb->get_input('deactivate') === '1' &&
            $method['className']::canBeDeactivated() &&
            isset($userMethods[$mybb->input['method']])
        ) {
            $output = $method['className']::handleDeactivation($user, $setupUrl);
        } else {
            add_breadcrumb($lang->my2fa_title, $setupUrl);
            add_breadcrumb($method['definitions']['name']);

            if (
                $mybb->get_input('activate') === '1' &&
                $method['className']::canBeDeactivated() &&
                !isset($userMethods[$mybb->input['method']])
            ) {
                $setupFormButtons = eval(template('setup_form_buttons'));

                $output = $method['className']::handleActivation(
                    $user,
                    $setupUrl,
                    compact(
                        'setupFormButtons'
                    )
                );
            } elseif (
                $mybb->get_input('manage') === '1' &&
                $method['className']::canBeManaged() &&
                isset($userMethods[$mybb->input['method']])
            ) {
                $output = $method['className']::handleManagement($user, $setupUrl);
            }
        }
    } else {
        add_breadcrumb($lang->my2fa_title);

        $setupMethodRows = null;
        foreach ($methods as $method) {
            if (!$method['className']::canBeActivated()) {
                continue;
            }

            if (!isset($userMethods[$method['id']])) {
                $setupMethodRows .= eval(template('setup_methods_row'));
            } else {
                $userMethod = $userMethods[$method['id']];

                $lang->my2fa_setup_method_activation_date = $lang->sprintf(
                    $lang->my2fa_setup_method_activation_date,
                    my_date($mybb->settings['dateformat'], $userMethod['activated_on'] ?? 0)
                );
                $lang->my2fa_setup_deactivate_confirmation = $lang->sprintf(
                    $lang->my2fa_setup_deactivate_confirmation,
                    $method['definitions']['name']
                );

                if ($method['className']::canBeDeactivated()) {
                    $setupDeactivateButton = eval(template('setup_button_deactivate'));
                }

                $setupManageButton = '';

                if ($method['className']::canBeManaged()) {
                    $setupManageButton = eval(template('setup_button_manage'));
                }

                $setupMethodRows .= eval(template('setup_methods_row_enabled'));
            }
        }

        $trustedDevices = null;
        if (
            isDeviceTrustingAllowed() &&
            doesUserHave2faEnabled($userID) &&
            (
            $userTokens = selectUserTokens($userID, [], [
                'order_by' => 'generated_on',
                'order_dir' => 'DESC'
            ])
            )
        ) {
            $currentUserToken = $userTokens[$mybb->cookies['my2fa_token']] ?? [];
            $otherUserTokens = $userTokens;

            if ($currentUserToken) {
                unset($otherUserTokens[$currentUserToken['tid']]);
            }

            if ($mybb->get_input('remove_trusted_devices') === '1') {
                verify_post_check($mybb->get_input('my_post_key'));

                if ($mybb->get_input('current') === '1' && $currentUserToken) {
                    deleteUserTokens($userID, (array)$currentUserToken['tid']);
                    redirect($setupUrl, $lang->my2fa_current_trusted_device_removed_success);
                } elseif ($mybb->get_input('others') === '1' && $otherUserTokens) {
                    deleteUserTokens($userID, array_column($otherUserTokens, 'tid'));
                    redirect($setupUrl, $lang->my2fa_other_trusted_devices_removed_success);
                }
            }

            $currentTrustedDeviceRow = null;
            if ($currentUserToken) {
                $lang->my2fa_setup_current_trusted_device = $lang->sprintf(
                    $lang->my2fa_setup_current_trusted_device,
                    my_date('relative', $userTokens[$mybb->cookies['my2fa_token']]['expire_on'])
                );

                $currentTrustedDeviceRow = eval(template('setup_trusted_devices_row_current'));
            }

            $otherTrustedDevicesRow = null;
            if ($otherUserTokens) {
                $lang->my2fa_setup_other_trusted_devices = $lang->sprintf(
                    $lang->my2fa_setup_other_trusted_devices,
                    count($otherUserTokens)
                );

                $otherTrustedDevicesLogRows = null;
                foreach ($otherUserTokens as $otherUserToken) {
                    $otherUserToken['generated_on_formatted'] = my_date('normal', $otherUserToken['generated_on']);
                    $otherUserToken['expire_on_formatted'] = my_date('normal', $otherUserToken['expire_on']);

                    $otherTrustedDevicesLogRows .= eval(template('setup_trusted_devices_row_others_row_log'));
                }

                $otherTrustedDevicesRow = eval(template('setup_trusted_devices_row_others'));
            }

            $trustedDevices = eval(template('setup_trusted_devices'));
        }

        $output = eval(template('setup'));
    }

    return $output;
}

// Based on admin/inc/class_page.php pattern
function getAdminVerificationPage(string $verificationContent): string
{
    global $mybb, $lang, $theme;

    $copyYear = COPY_YEAR;

    $stylesheetLocations = getDefaultGlobalStylesheetLocations();

    $stylesheetHtml = null;
    foreach ($stylesheetLocations as $stylesheetLocation) {
        $stylesheetHtml .= <<<HTML
<link rel="stylesheet" type="text/css" href="{$mybb->settings['bburl']}/{$stylesheetLocation}" />\n\t
HTML;
    }

    return <<<HTML
<!DOCTYPE html>
<html>
<head>
    <title>{$lang->my2fa_title}</title>
    <meta name="author" content="MyBB Group" />
    <meta name="copyright" content="Copyright {$copyYear} MyBB Group." />
    {$stylesheetHtml}
    <style>
        body, html, #container { height: 100%; margin: 0; }
        #container { display: flex; align-items: center; justify-content: center; text-align: left; }
        #verification-wrap { flex: 1; }
    </style>
</head>
<body>
    <div id="container">
        <div id="verification-wrap">
            {$verificationContent}
        </div>
    </div>
</body>
</html>
HTML;
}
