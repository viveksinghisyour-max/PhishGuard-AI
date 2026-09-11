import { Link } from "react-router-dom";

function Login() {
  return (
    <div className="min-h-screen bg-[#1d2439] text-[#f5eee2] flex items-center justify-center px-6">

      <div className="w-full max-w-[456px]">

        {/* Top Navigation */}
        <div className="flex items-center gap-9 border-b border-[#3a4155]">

          <Link
            to="/login"
            className="relative pb-5 text-[18px] font-medium text-[#f5eee2]"
          >
            Sign in

            {/* Active underline */}
            <span className="absolute bottom-[-1px] left-0 h-[2px] w-[61px] bg-[#d1a653]" />
          </Link>

          <Link
            to="/register"
            className="pb-5 text-[18px] font-medium text-[#9da8c2] transition hover:text-[#f5eee2]"
          >
            Create account
          </Link>

        </div>

        {/* Login Content */}
        <div className="pt-11">

          {/* Heading */}
          <h1 className="font-serif text-[34px] leading-tight font-medium tracking-tight text-[#f5eee2]">
            Welcome back
          </h1>

          <p className="mt-4 text-[17px] text-[#9da8c2]">
            Sign in to your ThreatX security platform.
          </p>

          {/* Email */}
          <div className="mt-9">

            <label
              htmlFor="email"
              className="mb-3 block text-[16px] font-semibold text-[#f5eee2]"
            >
              Email
            </label>

            <input
              id="email"
              type="email"
              placeholder="you@example.com"
              className="h-[54px] w-full rounded-[4px] border border-[#3c4560] bg-[#282f49] px-4 text-[17px] text-[#f5eee2] outline-none placeholder:text-[#65718e] transition focus:border-[#d1a653]"
            />

          </div>

          {/* Password */}
          <div className="mt-6">

            <label
              htmlFor="password"
              className="mb-3 block text-[16px] font-semibold text-[#f5eee2]"
            >
              Password
            </label>

            <input
              id="password"
              type="password"
              placeholder="Your password"
              className="h-[54px] w-full rounded-[4px] border border-[#3c4560] bg-[#282f49] px-4 text-[17px] text-[#f5eee2] outline-none placeholder:text-[#65718e] transition focus:border-[#d1a653]"
            />

          </div>

          {/* Remember + Forgot */}
          <div className="mt-6 flex items-center justify-between">

            <label className="flex cursor-pointer items-center gap-2 text-[16px] text-[#f5eee2]">
              <input
                type="checkbox"
                className="h-[15px] w-[15px] accent-[#d1a653]"
              />

              <span>Remember me</span>
            </label>

            <button
              type="button"
              className="text-[16px] font-medium text-[#d1a653] transition hover:text-[#e2bc68]"
            >
              Forgot password?
            </button>

          </div>

          {/* Sign In Button */}
          <button
            type="button"
            className="mt-8 h-[57px] w-full rounded-[4px] bg-[#d1a653] text-[18px] font-semibold text-black transition hover:bg-[#dfb967] active:scale-[0.99]"
          >
            Sign in
          </button>

          {/* Register */}
          <p className="mt-8 text-center text-[16px] text-[#9da8c2]">
            New to ThreatX?{" "}

            <Link
              to="/register"
              className="font-semibold text-[#d1a653] transition hover:text-[#e2bc68]"
            >
              Create an account
            </Link>
          </p>

        </div>

      </div>

    </div>
  );
}

export default Login;