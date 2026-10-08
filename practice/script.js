const canvas = document.getElementById("codeGrid");

const ctx = canvas.getContext("2d");

let width;
let height;

let dpr;

const mouse = {
    x: -1000,
    y: -1000,

    targetX: -1000,
    targetY: -1000
};

const operators = [
    "+",
    "-",
    "×",
    "÷",
    "=",
    "<",
    ">",
    "/",
    "*",
    "%",
    "{",
    "}",
    "[",
    "]",
    "(",
    ")",
    "&",
    "|",
    "^",
    ":",
    ";"
];

const colors = [
    "#FF4D6D",
    "#FF8A00",
    "#FFD60A",
    "#00C2FF",
    "#7C4DFF",
    "#00D084",
    "#FF3CAC"
];

let tiles = [];

const settings = {

    tileSize: 42,

    gap: 7,

    interactionRadius: 180,

    maxScale: 1.35,

    animationSpeed: 0.12
};



function resize() {

    dpr = window.devicePixelRatio || 1;

    width = window.innerWidth;

    height = window.innerHeight;

    canvas.width = width * dpr;

    canvas.height = height * dpr;

    canvas.style.width = width + "px";

    canvas.style.height = height + "px";

    ctx.setTransform(
        dpr,
        0,
        0,
        dpr,
        0,
        0
    );

    createGrid();
}

window.addEventListener("resize", resize);

function createGrid() {

    tiles = [];

    const step =
        settings.tileSize +
        settings.gap;

    const columns =
        Math.ceil(width / step) + 2;

    const rows =
        Math.ceil(height / step) + 2;

    const offsetX =
        (width - columns * step) / 2;

    const offsetY =
        (height - rows * step) / 2;

    for (let row = 0; row < rows; row++) {

        for (let column = 0; column < columns; column++) {

            const x =
                offsetX +
                column * step;

            const y =
                offsetY +
                row * step;

            tiles.push({

                x,
                y,

                size: settings.tileSize,

                operator:
                    operators[
                        Math.floor(
                            Math.random() *
                            operators.length
                        )
                    ],

                color:
                    colors[
                        Math.floor(
                            Math.random() *
                            colors.length
                        )
                    ],

                influence: 0,

                currentScale: 1,

                rotation: 0,

                opacity: 0.25
            });
        }
    }
}

window.addEventListener("mousemove", (event) => {

    mouse.targetX = event.clientX;

    mouse.targetY = event.clientY;

});

function updateMouse() {

    mouse.x +=
        (mouse.targetX - mouse.x) * 0.15;

    mouse.y +=
        (mouse.targetY - mouse.y) * 0.15;
}

