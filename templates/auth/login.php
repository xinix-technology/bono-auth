<form action="" method="POST">
    <div class="field-username">
        <label>Username</label>
        <input type="text" name="username" value="<?php echo @$entry['username'] ?>">
    </div>
    <div class="field-password">
        <label>Password</label>
        <input type="password" name="password">
    </div>
    <input type="hidden" name="keep" value="1">
    <div class="row">
        <input type="submit" value="Login">
    </div>
</form>
