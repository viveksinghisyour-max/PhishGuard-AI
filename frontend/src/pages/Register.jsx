import { Link } from "react-router-dom";

function Register() {
  return (
    <div className="min-h-screen bg-[#1d2439] text-[#f5eee2] flex items-center justify-center px-6 py-10">

      <div className="w-full max-w-[456px]">

        {/* Top Navigation */}
        <div className="flex items-center gap-9 border-b border-[#3a4155]">

          <Link
            to="/login"
            className="pb-5 text-[18px] font-medium text-[#9da8c2] transition hover:text-[#f5eee2]"
          >
            Sign in
          </Link>

          <Link
            to="/register"
            className="relative pb-5 text-[18px] font-medium text-[#f5eee2]"
          >
            Create account

            {/* Active underline */}
            <span className="absolute bottom-[-1px] left-0 h-[2px] w-[122px] bg-[#d1a653]" />
          </Link>

        </div>

        {/* Register Content */}
        <div className="pt-11">

          {/* Heading */}
          <h1 className="font-serif text-[34px] leading-tight font-medium tracking-tight text-[#f5eee2]">
            Create account
          </h1>

          <p className="mt-4 text-[17px] text-[#9da8c2]">
            Join the ThreatX security platform.
          </p>

          {/* Full Name */}
          <div className="mt-8">

            <label
              htmlFor="name"
              className="mb-3 block text-[16px] font-semibold text-[#f5eee2]"
            >
              Full Name
            </label>

            <input
              id="name"
              type="text"
              placeholder="Enter your full name"
              className="h-[54px] w-full rounded-[4px] border border-[#3c4560] bg-[#282f49] px-4 text-[17px] text-[#f5eee2] outline-none placeholder:text-[#65718e] transition focus:border-[#d1a653]"
            />

          </div>

          {/* Email */}
          <div className="mt-6">

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
              placeholder="Create a password"
              className="h-[54px] w-full rounded-[4px] border border-[#3c4560] bg-[#282f49] px-4 text-[17px] text-[#f5eee2] outline-none placeholder:text-[#65718e] transition focus:border-[#d1a653]"
            />

          </div>

          {/* Confirm Password */}
          <div className="mt-6">

            <label
              htmlFor="confirmPassword"
              className="mb-3 block text-[16px] font-semibold text-[#f5eee2]"
            >
              Confirm Password
            </label>

            <input
              id="confirmPassword"
              type="password"
              placeholder="Confirm your password"
              className="h-[54px] w-full rounded-[4px] border border-[#3c4560] bg-[#282f49] px-4 text-[17px] text-[#f5eee2] outline-none placeholder:text-[#65718e] transition focus:border-[#d1a653]"
            />

          </div>

          {/* Register Button */}
          <button
            type="button"
            className="mt-8 h-[57px] w-full rounded-[4px] bg-[#d1a653] text-[18px] font-semibold text-black transition hover:bg-[#dfb967] active:scale-[0.99]"
          >
            Create account
          </button>

          {/* Login */}
          <p className="mt-8 text-center text-[16px] text-[#9da8c2]">
            Already have an account?{" "}

            <Link
              to="/login"
              className="font-semibold text-[#d1a653] transition hover:text-[#e2bc68]"
            >
              Sign in
            </Link>
          </p>

        </div>

      </div>

    </div>
  );
}

export default Register;