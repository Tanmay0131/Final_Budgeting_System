<?php
session_start();
if(!isset($_SESSION['authcode'])){
    header("location:login.php");
}
use GetUser\Client\GraphApiClient;
use Microsoft\Kiota\Abstractions\ApiException;
use Microsoft\Kiota\Authentication\Oauth\AuthorizationCodeContext;
use Microsoft\Kiota\Authentication\PhpLeagueAuthenticationProvider;
use Microsoft\Kiota\Http\GuzzleRequestAdapter;
 
require __DIR__.'/vendor/autoload.php';
 
try {
    $clientId = 'baf988fb-4544-4dcf-a47d-4e21a533c2db';
    $clientSecret = 'gh88Q~Z5S9YPafojtomr6qOo-osGsufKmil5ia90';
    //$authorizationCode = '0.ARIAi9dP4430NUKXh_73ZyO-FPuI-bpERc9NpH1OIaUzwtvWAAA.AgABAAIAAAAtyolDObpQQ5VtlI4uGjEPAgDs_wUA9P8tNGqWJO4Kq7yfYQRxnwdHj2j3c4hrAPOLnZfdE9EpVmNofS6Y0Dp9V1-hvV9Lkg5L7M90zhpbaNslyX0Te80dn7NT5ZuWIUROyToTaIrNPP3CMFA0RR6el0n9zD9HCmxGtZzElTczouw99uvfSGQ9nF77lGbO07Kg6HBznlg3-tONxDS6wjmrER1oSMgksZWZSc7xjLHIdUFd0ITJZicZgAFEpQRs8c7W6Rv0KGq040c4E8yiYTgY1SKWB5LdzPfbZdI3KJZDM4XnB5Bx3XNXBh3wEk-JI7DKnnICZ1kbL_b2whdTBb6zjq2UMhnVsoy6HM9pNe1xzj7lPvF66ppZ-qawiVWjbNjfC-3Zg2a7KaMOqmfgTWIMgkG2Fvfux9_GoPcCKJmYAy-0QF0Dbb2Z5ommELXSuzR_eyZWFyFi1VvvaWEqui9t9-xiIKnHQwGEYSv-6x7C2MP3qq2nQNe--CipM9tGEMHQtInFZgCJKS7U891eUv5Wmqv9hLFXrrhPDOQZrtnkUZiqRB5qt455gDMcTICqnWptUlkYwY9hphu6deRlfwLvFc-JOOrT8IztP9ks6Uc5vFZpFqsMwQBtXQz-wtfY7vMIlUwG0JThChyF6HXGlFoT_35-1GS2wO0HBA';
    $authorizationCode = $_SESSION['authcode'];
 
    $tenantId = 'e34fd78b-f48d-4235-9787-fef76723be14';
    $redirectUri = 'http://localhost/tanmayPython/handle.php';
 
    // The auth provider will only authorize requests to
    // the allowed hosts, in this case Microsoft Graph
    $allowedHosts = ['graph.microsoft.com'];
    $scopes = ['User.Read'];
 
    $tokenRequestContext = new AuthorizationCodeContext(
        $tenantId,
        $clientId,
        $clientSecret,
        $authorizationCode,
        $redirectUri
    );
 
    $authProvider = new PhpLeagueAuthenticationProvider($tokenRequestContext, $scopes, $allowedHosts);
    $requestAdapter = new GuzzleRequestAdapter($authProvider);
    $client = new GraphApiClient($requestAdapter);
 
    $me = $client->me()->get()->wait();
    $_SESSION["MSDisplayName"] = $me->getDisplayName();
    echo "Hello {$me->getDisplayName()}, your ID is {$me->getId()}<br>";
    echo "<pre>";
    echo print_r($me);
    echo "</pre>";
 
} catch (ApiException $ex) {
    header("location:login.php?{$ex->getMessage()}");
    echo $ex->getMessage();
} catch(Exception $e){
    header("location:login.php?{$e->getMessage()}");
}
?>