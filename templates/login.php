<?php
// FIXME this logic should be in hook or filter
// if login then redirect
if (isset($entry)):
    if (!empty($_GET['continue'])) {
        $continue = $_GET['continue'];
    } else {
        $continue = '/';
    }
    $response->redirect($continue);
endif
?>

<form action="" method="POST">
    <div class="row field field-username">
        <label>Username</label>
        <input type="text" name="username" value="<?php echo @$entry['username'] ?>">
    </div>
    <div class="row field field-password">
        <label>Password</label>
        <input type="password" name="password">
    </div>
    <div class="row">
        <input type="submit" value="Login">
    </div>
</form>