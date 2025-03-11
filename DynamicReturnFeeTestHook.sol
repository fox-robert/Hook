// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {SafeCast, Hooks, IHooks, IPoolManager, PoolKey, Currency, CurrencyLibrary, BalanceDelta, BalanceDeltaLibrary, toBeforeSwapDelta, BeforeSwapDelta, BeforeSwapDeltaLibrary, LPFeeLibrary} from "./IUniswapV4.sol";

contract DynamicReturnFeeTestHook is IHooks {
    using Hooks for IHooks;
    using LPFeeLibrary for uint24;

    uint24 public fee;
    IPoolManager public poolManager;
    mapping(Currency => uint) public feePriority;

    event Hooked(uint160 indexed flag);

    function setManager(IPoolManager poolManager_) external {
        poolManager = poolManager_;
    }

    function setFeePriority(Currency currency, uint priority) external {
        feePriority[currency] = priority;
    }
    
    function setFee(uint24 lpFee) external {
        fee = lpFee;
    }

    function updateDynamicLPFee(PoolKey calldata key, uint24 lpFee) external {
        poolManager.updateDynamicLPFee(key, lpFee);
    }

    function beforeInitialize(address, PoolKey calldata, uint160) external override returns (bytes4) {
        emit Hooked(Hooks.BEFORE_INITIALIZE_FLAG);
        return IHooks.beforeInitialize.selector;
    }

    function afterInitialize(address, PoolKey calldata key, uint160, int24) external override returns (bytes4) {
        poolManager.updateDynamicLPFee(key, fee);
        emit Hooked(Hooks.AFTER_INITIALIZE_FLAG);
        return IHooks.afterInitialize.selector;
    }

    function beforeAddLiquidity(address, PoolKey calldata, IPoolManager.ModifyLiquidityParams calldata, bytes calldata)
        external
        override
        returns (bytes4)
    {
        emit Hooked(Hooks.BEFORE_ADD_LIQUIDITY_FLAG);
        return IHooks.beforeAddLiquidity.selector;
    }

    function afterAddLiquidity(
        address,
        PoolKey calldata,
        IPoolManager.ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external override returns (bytes4, BalanceDelta) {
        emit Hooked(Hooks.AFTER_ADD_LIQUIDITY_FLAG);
        return (IHooks.afterAddLiquidity.selector, BalanceDeltaLibrary.ZERO_DELTA);
    }

    function beforeRemoveLiquidity(
        address,
        PoolKey calldata,
        IPoolManager.ModifyLiquidityParams calldata,
        bytes calldata
    ) external override returns (bytes4) {
        emit Hooked(Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG);
        return IHooks.beforeRemoveLiquidity.selector;
    }

    function afterRemoveLiquidity(
        address,
        PoolKey calldata,
        IPoolManager.ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external override returns (bytes4, BalanceDelta) {
        emit Hooked(Hooks.AFTER_REMOVE_LIQUIDITY_FLAG);
        return (IHooks.afterRemoveLiquidity.selector, BalanceDeltaLibrary.ZERO_DELTA);
    }

    function beforeSwap(address, PoolKey calldata key, IPoolManager.SwapParams calldata params, bytes calldata)
        external
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        emit Hooked(Hooks.BEFORE_SWAP_FLAG);
        (Currency currencyInput, Currency currencyOutput) = params.zeroForOne ? (key.currency0, key.currency1) : (key.currency1, key.currency0);
        (uint priorityInput, uint priorityOutput) = (feePriority[currencyInput], feePriority[currencyOutput]);
        if(priorityInput >= priorityOutput) {
            // attach the fee flag to `fee` to enable overriding the pool's stored fee
            return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, fee | LPFeeLibrary.OVERRIDE_FEE_FLAG);
        } else if(params.amountSpecified > 0) {
            uint hookFee = uint(params.amountSpecified) * fee / LPFeeLibrary.MAX_LP_FEE;
            (uint fee0, uint fee1) = params.zeroForOne ? (uint(0), hookFee) : (hookFee, 0);
            poolManager.donate(key, fee0, fee1, "");
            return (IHooks.beforeSwap.selector, toBeforeSwapDelta(int128(int(hookFee)), 0), 0 | LPFeeLibrary.OVERRIDE_FEE_FLAG);     // hookFee instead of lpFee
        } else
            return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0 | LPFeeLibrary.OVERRIDE_FEE_FLAG);     // hookFee instead of lpFee
    }

    function afterSwap(address, PoolKey calldata key, IPoolManager.SwapParams calldata params, BalanceDelta delta, bytes calldata)
        external
        override
        returns (bytes4, int128)
    {
        emit Hooked(Hooks.AFTER_SWAP_FLAG);
        uint priorityInput;
        uint priorityOutput;
        Currency currencyOutput;
        {
        Currency currencyInput;
        (currencyInput, currencyOutput) = params.zeroForOne ? (key.currency0, key.currency1) : (key.currency1, key.currency0);
        (priorityInput, priorityOutput) = (feePriority[currencyInput], feePriority[currencyOutput]);
        }
        if(priorityInput < priorityOutput && params.amountSpecified < 0) {
            int128 amountUnspecified = params.zeroForOne ? delta.amount1() : delta.amount0();
            uint256 hookFee = uint256(int256(amountUnspecified)) * fee / LPFeeLibrary.MAX_LP_FEE;
            (uint fee0, uint fee1) = params.zeroForOne ? (uint(0), hookFee) : (hookFee, 0);
            poolManager.donate(key, fee0, fee1, "");
            return (IHooks.afterSwap.selector, SafeCast.toInt128(hookFee));
        } else
            return (IHooks.afterSwap.selector, 0);
    }

    function beforeDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        external
        override
        returns (bytes4)
    {
        emit Hooked(Hooks.BEFORE_DONATE_FLAG);
        return IHooks.beforeDonate.selector;
    }

    function afterDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        external
        override
        returns (bytes4)
    {
        emit Hooked(Hooks.AFTER_DONATE_FLAG);
        return IHooks.afterDonate.selector;
    }
}
