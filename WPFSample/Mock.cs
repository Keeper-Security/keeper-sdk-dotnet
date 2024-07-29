namespace WPFSample
{
    public class MockLoginModel
    {
        public MockLoginModel()
        {
            StepData = new UsernameLoginStep { Username = "username@company.com" };
            //StepData = new ApproveDeviceMethods(new[] {DeviceApprovalChannel.Email, DeviceApprovalChannel.KeeperPush, DeviceApprovalChannel.TwoFactorAuth});
            //StepData = new VerificationCodeStep("Email", "Enter verification code recieved by email");
            //StepData = new EnterMasterPasswordStep("username@company.com");
            //ErrorText = "The code you entered is incorrect.";
        }

        public ILoginStep StepData { get; }

        public string ErrorText { get; }
    }
}
