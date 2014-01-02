<form action="" method="POST">
    <div class="row">
        <label>Username</label>
        <input type="text" name="username" value="<?php echo @$entry['username'] ?>">
    </div>
    <div class="row">
        <label>Password</label>
        <input type="password" name="password">
    </div>
    <div class="row">
        <input type="submit" value="Login">
    </div>
</form>