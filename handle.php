<?php
    session_start();
    $_SESSION['authcode'] = $_GET["code"];
    header("location:./GetUser.php");
?>